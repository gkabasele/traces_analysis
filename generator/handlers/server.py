#!/usr/bin/python
import os
import sys
import logging
from logging.handlers import RotatingFileHandler
import SocketServer
import threading
import multiprocessing
import socket
import errno
import argparse
import cPickle as pickle
import select
import struct
import time
import Queue
import zlib
import datetime
from traceback import format_exception
from traceback import print_exc
from util import Sender, Receiver
from util import get_tcp_info, create_logger
import flowDAO as flowDAO

parser = argparse.ArgumentParser()
parser.add_argument("--addr", type=str, dest="ip", action="store", help="ip address of the host")
parser.add_argument("--port", type=int, dest="port", action="store", help="port of the service")
parser.add_argument("--proto", type=str, dest="proto", action="store", help="protocol used for the flow")
group = parser.add_mutually_exclusive_group(required=True)
group.add_argument("--pipe", action="store_true")
group.add_argument("--sock", action="store_true")

subparsers = parser.add_subparsers(help="entry type to receive flow request")

parser_pipe = subparsers.add_parser("pipe", help="named pipe")
parser_pipe.add_argument("--pipename", type=str, dest="pipename",
                         action="store")

parser_sock = subparsers.add_parser("sock", help="socket")
parser_sock.add_argument("--sock_ip", type=str, dest="sock_ip", action="store")
parser_sock.add_argument("--sock_port", type=int, dest="sock_port", action="store")

args = parser.parse_args()

port = args.port
ip = args.ip
proto = args.proto
flowproto = 6 if args.proto == "tcp" else 17

logger = logging.getLogger()
logger.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s :: %(levelname)s :: %(message)s')
logname = '../logs/server_%s:%d:%s.log' % (ip, port, flowproto)
if os.path.exists(logname):
    os.remove(logname)

file_handler = RotatingFileHandler(logname, 'a', 1000000, 1)
file_handler.setLevel(logging.DEBUG)
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)

def create_chunk(size):
    return os.urandom(size)

def log_exception(etype, val, tb):
    logger.exception("%s", "".join(format_exception(etype, val, tb)))

sys.excepthook = log_exception

class ThreadPoolMixIn:

    # Size of pool
    pool_size = 15

    # How long to wait on a empty queue, in seconds. Can be a float.
    timeout_on_get = 0.5

    def __init__(self):
        self._request_queue = Queue.Queue(self.pool_size)
        self._shutdown_event = threading.Event()
        for _ in xrange(self.pool_size):
            thread = threading.Thread(target=self.process_request_thread)
            thread.setDaemon(1)
            thread.start()

    def process_request_thread(self):
        while True:
            try:
                request, client_address = self._request_queue.get(
                    timeout=self.timeout_on_get,
                )
            except Queue.Empty:
                sys.exc_clear()
                if self._shutdown_event.isSet():
                    return
                continue
            try:
                logger.debug("Handling request for client %s", client_address)
                self.finish_request(request, client_address)
                self.shutdown_request(request)
            except:
                self.handle_error(request, client_address)
                self.shutdown_request(request)
            self._request_queue.task_done()

    def process_request(self, request, client_address):
        logger.debug("Server %s got request from %s placing it in the queue",
                     self.server_address, client_address)
        self._request_queue.put((request, client_address))

    def join(self):
        self._request_queue.join()
        self._shutdown_event.set()

class TCPFlowRequestHandler(SocketServer.StreamRequestHandler):
    """
    The RequestHandler class for our server.

    It is instantiated once per connection to the server, and must
    override the handle() method to implement communication to the
    client.
    """

    def __init__(self, request, client_address, server, pkt_gen=None,
                 arr_gen=None, first=None, rem_first=None, nbr_pkt=None,
                 rem_nbr_pkt=None):

        self.logname = "../logs/server_{}:{}__{}:{}:6.log".format(server.server_address[0],
                                                                  server.server_address[1],
                                                                  client_address[0],
                                                                  client_address[1])
        self.logger = create_logger(self.logname)
        logger.debug("Initialization of the TCP Handler for %s", client_address)
        self.pkt_gen = pkt_gen
        self.arr_gen = arr_gen
        self.first = first
        self.rem_first = rem_first
        self.nbr_pkt = nbr_pkt
        self.rem_nbr_pkt = rem_nbr_pkt
        SocketServer.StreamRequestHandler.__init__(self, request, client_address,
                                                   server)

    def read_flow_from_queue(self):
        tries = 0
        while tries < 3:
            try:
                gen = self.server.map_client[self.client_address].get(timeout=0.5)
                if gen:
                    return gen
                else:
                    raise ValueError('Invalid message from queue')
            except Queue.Empty:
                self.logger.debug("Could not read stats for flow to %s, queue empty",
                             self.client_address)
                time.sleep(0.01)
                tries += 1
                self.logger.debug("Retriying to read: %d", tries)

    def setup(self):
        self.connection = self.request
        if self.timeout is not None:
            self.connection.settimeout(self.timeout)
        self.connection.setsockopt(socket.IPPROTO_TCP,
                                   socket.TCP_NODELAY, True)
        self.rfile = self.connection.makefile('rb', self.rbufsize)
        self.wfile = self.connection.makefile('wb', self.wbufsize)

    def finish(self):
        self.logger.debug("Done handling request for %s", self.client_address)
        if not self.wfile.closed:
            try:
                self.wfile.flush()
            except socket.error():
                # A final socket error may have occurred here, such as
                # the local error ECONNABORTED
                pass
        self.wfile.close()
        self.rfile.close()

    def _send_msg(self, msg):
        # Prefix each message with a 4-byte length (network byte order)
        msg = struct.pack('>I', len(msg)) + msg
        self.request.sendall(msg)
        return len(msg)

    def _recv_msg(self):
        raw_msglen = self._recvall(4)
        if not raw_msglen:
            return None
        msglen = struct.unpack('>I', raw_msglen)[0]
        return self._recvall(msglen)

    def _recvall(self, n):
        data = b''
        while len(data) < n:
            packet = self.request.recv(n - len(data))
            if not packet:
                return None
            data += packet
        return data

    def create_sender(self, name, cur_pkt_ts, rem_cur_pkt_ts, nbr_pkt, arr_gen, pkt_gen,
                      rem_ip, rem_port):
        first_arr = 0
        if rem_cur_pkt_ts and cur_pkt_ts:
            if cur_pkt_ts > rem_cur_pkt_ts:
                first_arr = cur_pkt_ts - rem_cur_pkt_ts

        sender = Sender(name, nbr_pkt, arr_gen, pkt_gen, first_arr,
                        self.request, self.server.lock, rem_ip, rem_port, True,
                        self.logname)

        return sender

    def redefine_sender(self, sender, cur_pkt_ts, rem_cur_pkt_ts, nbr_pkt,
                        arr_gen, pkt_gen):
        first_arr = 0
        if rem_cur_pkt_ts and cur_pkt_ts:
            if cur_pkt_ts > rem_cur_pkt_ts:
                first_arr = cur_pkt_ts - rem_cur_pkt_ts

        sender.reset_params(nbr_pkt, arr_gen, pkt_gen, first_arr)

    def _set_flow_generator(self, pkt_gen, arr_gen, first, rem_first, nbr_pkt,
                            rem_nbr_pkt):
        self.pkt_gen = pkt_gen
        self.arr_gen = arr_gen
        self.first = first
        self.rem_first = rem_first
        self.nbr_pkt = nbr_pkt
        self.rem_nbr_pkt = rem_nbr_pkt

    def wait_sender(self, sender, timeout=0.005):
        while not sender.done:
            time.sleep(timeout)

    def create_receiver(self, rem_nbr_pkt, rem_ip, rem_port, last):

        receiver = Receiver("receiver", rem_nbr_pkt, rem_ip, rem_port,
                            self.request, self.server.lock, True, last, self.logname)
        return receiver

    def handle(self):

        sender = None
        receiver = None
        frame_index = 0

        while True:
            self.logger.debug("Starting sending in frame index: %s for %s", frame_index,
                              self.client_address)
            s = self.read_flow_from_queue()

            if s is None:
                self.logger.debug("Could not read from queue, %s",
                                  self.client_address)
                return

            self._set_flow_generator(s.pkt_gen, s.arr_gen, s.first, s.rem_first,
                                     s.nbr_pkt, s.rem_nbr_pkt)

            fst_str = None
            rem_str = None
            if s.first:
                fst_str = datetime.datetime.fromtimestamp(s.first/1000.0).strftime('%d-%m-%Y:%H:%M:%S:%f')
            if s.rem_first:
                rem_str = datetime.datetime.fromtimestamp(s.rem_first/1000.0).strftime('%d-%m-%Y:%H:%M:%S:%f')

            self.logger.debug("#Loc_pkt: %d, #Rem_pkt: %d, fst: %s, rem_fst: %s to client %s",
                              s.nbr_pkt,
                              s.rem_nbr_pkt,
                              fst_str,
                              rem_str,
                              self.client_address)
            cur_pkt_ts = self.first
            rem_cur_pkt_ts = self.rem_first
            if not sender and not receiver:
                receiver = self.create_receiver(s.rem_nbr_pkt,
                                                self.client_address[0],
                                                self.client_address[1],
                                                s.last)
                receiver.start()

                sender = self.create_sender("sender", cur_pkt_ts, rem_cur_pkt_ts,
                                            self.nbr_pkt, self.arr_gen,
                                            self.pkt_gen, self.client_address[0],
                                            self.client_address[1])
                sender.start()
            else:
                receiver.queue.put((s.rem_nbr_pkt, s.last))
                logger.debug("Redefining receiver for %s:%s",
                             self.client_address[0], self.client_address[1])

                self.redefine_sender(sender, self.first, self.rem_first,
                                     self.nbr_pkt, self.arr_gen, self.pkt_gen)
                logger.debug("Redefining sender for %s:%s",
                             self.client_address[0], self.client_address[1])

            self.wait_sender(sender)

            if s.last:
                sender.queue.put(True)
                if sender.is_alive():
                    sender.join()
                if receiver.is_alive():
                    receiver.join()
                self.logger.debug("Flow generation completely done for %s", self.client_address)
                break
            frame_index += 1

class FlowTCPServer(ThreadPoolMixIn, SocketServer.TCPServer):

    def __init__(self, server_address, is_pipe_entry, pipename=None,
                 handler_class=TCPFlowRequestHandler, sock_ip=None,
                 sock_port=None):
        logger.debug("Initializing TCP server")

        self.map_client = {}
        self.stop = False

        ThreadPoolMixIn.__init__(self)
        SocketServer.TCPServer.__init__(self, server_address, handler_class)

        if is_pipe_entry:
            logger.debug("Initializing pipe")
            if not os.path.exists(pipename):
                logger.debug("Pipe %s does not exist", pipename)
                raise ValueError("Pipe {} does not exist".format(pipename))
            self.reader = flowDAO.FlowRequestPipeReader(pipename)
        else:
            logger.debug("Initializing socket")
            self.reader = flowDAO.FlowRequestSockReader(sock_ip, sock_port)
            self.reader.start()
        self.lock = threading.RLock()
        logger.debug("Server initialized")

        self.socket.setblocking(0)

    def __str__(self):
        return "{}:{}".format(self.server_address[0], self.server_address[1])

    def __repr__(self):
        return self.__str__()

    def serve_forever(self):
        pipe_thr = threading.Thread(target=self.listen_pipe, args=())
        pipe_thr.start()
        SocketServer.TCPServer.serve_forever(self)

    def listen_pipe(self):
        while True:
            readable, _, _ = select.select([self.reader.entry_point],
                                           [],
                                           [],
                                           1)
            if readable:
                msg = self.reader.read()
                try:
                    gen = pickle.loads(zlib.decompress(msg))
                    client_addr = (gen.rem_ip, gen.rem_port)
                    logger.debug("Message for %s put in map", client_addr)
                    if client_addr in self.map_client:
                        self.map_client[client_addr].put_nowait(gen)
                    else:
                        self.map_client[client_addr] = Queue.Queue(maxsize=20)
                        self.map_client[client_addr].put_nowait(gen)

                except Queue.Full:
                    pass
                except ValueError:
                    pass

            if self.stop:
                break

    def read_flow_gen_from_pipe(self):
        logger.debug("Reading flow from generator from pipe")
        #msg = read_all_msg(self.pipeout)
        msg = self.reader.read()
        if msg:
            logger.debug("Reading message of size %d", len(msg))
            gen = pickle.loads(zlib.decompress(msg))
            return gen
        else:
            raise ValueError("Invalid message from pipe")

    def finish_request(self, request, client_address):
        self.RequestHandlerClass(request, client_address, self)

    def shutdown(self):
        self.reader.close()
        #TODO close Pipe Reading thread
        #os.close(self.pipeout)
        #os.remove(self.pipename)
        self.join()
        SocketServer.TCPServer.shutdown(self)

class UDPFlowRequestHandler(SocketServer.BaseRequestHandler):

    def __init__(self, request, client_address, server, arr_gen=None,
                 pkt_gen=None, first=None, rem_first=None,
                 nbr_pkt=None, rem_nbr_pkt=None):

        self.pkt_gen = pkt_gen
        self.arr_gen = arr_gen
        self.first = first
        self.rem_first = rem_first
        self.nbr_pkt = nbr_pkt
        self.rem_nbr_pkt = rem_nbr_pkt

        self.request = request
        self.client_address = client_address
        self.server = server
        try:
            self.handle()
        finally:
            self.finish()

    #FIXME check error
    def _send_msg(self, msg):
        # Prefix each message with a 4-byte length (network byte order)
        self.request[1].sendto(msg, self.client_address)
        return len(msg)

    def _recv_msg(self):
        data, _ = self.request[1].recvfrom(4096)
        return data

    def _recvall(self, n):
        data = b''
        while len(data) < n:
            packet, _ = self.request[1].recvfrom(n - len(data))[0]
            if not packet:
                return None
            data += packet
        return data

    def handle(self):

        j = 0
        cur_pkt_ts = self.first
        rem_cur_pkt_ts = self.rem_first
        error = True
        name = "server"
        threading.currentThread().setName("-".join([name, "receiver"]))
        try:
            first_arr = 0
            if rem_cur_pkt_ts and cur_pkt_ts > rem_cur_pkt_ts:
                first_arr = cur_pkt_ts - rem_cur_pkt_ts

            sender = Sender(name, self.nbr_pkt, self.arr_gen,
                            self.pkt_gen, first_arr,
                            self.request[1], self.server.lock,
                            self.client_address[0], self.client_address[1],
                            False, logname)
            sender.start()
            while j < self.rem_nbr_pkt:
                readable, _, _ = select.select([self.request[1]], [], [], 1)
                if readable:
                    self.server.lock.acquire()
                    data = self._recv_msg()
                    if data:
                        j += 1
                    self.server.lock.release()
                    logger.debug("Pkt %s/%s of %sB recv from %s",
                                 j, self.rem_nbr_pkt, len(data),
                                 self.client_address)

            logger.debug("All packet %d have been received from %s", j,
                         self.client_address)
            if sender.is_alive():
                sender.join()
            error = False

        except socket.error as msg:
            logger.debug("Socket error: %s", msg)
            if msg.errno == errno.EPIPE:
                return
        except Exception:
            logger.exception(print_exc())
        finally:
            if error:
                logger.debug("The flow generated does not match the requirement")
            try:
                self.server.lock.release()
            except threading.ThreadError:
                pass
            except RuntimeError:
                pass
    def finish_request(self):
        logger.debug("flow generated for %s", self.client_address)

class FlowUDPServer(ThreadPoolMixIn, SocketServer.UDPServer):

    def __init__(self, server_address, is_pipe_entry, pipename=None,
                 handler_class=UDPFlowRequestHandler, sock_ip=None,
                 sock_port=None):

        logger.debug("Initializing UDP server")
        ThreadPoolMixIn.__init__(self)
        SocketServer.UDPServer.__init__(self, server_address, handler_class)

        if is_pipe_entry:
            logger.debug("Initializing pipe")
            if not os.path.exists(pipename):
                logger.debug("Pipe %s does not exist", pipename)
                raise ValueError("Pipe {} does not exist".format(pipename))
            self.reader = flowDAO.FlowRequestPipeReader(pipename)
        else:
            logger.debug("Initializing socket")
            self.reader = flowDAO.FlowRequestSockReader(sock_ip, sock_port)
            self.reader.start()

        self.lock = threading.RLock()
        logger.debug("Server initialized")

    def __str__(self):
        return "{}:{}".format(self.server_address[0], self.server_address[1])

    def __repr__(self):
        return self.__str__()

    def get_flow_stats(self):
        logger.debug("Getting flow statistic for generation")
        tries = 0
        while True:
            logger.debug("Select on pipe")
            readable, wr, ex = select.select([self.reader.entry_point], [], [], 1)
            if readable:
                data = os.read(self.reader.entry_point, 1)
                if data == 'X':
                    raw_length = os.read(self.reader.entry_point, 4)
                    message = os.read(self.reader.entry_point, int(raw_length))
                    stats = pickle.loads(zlib.decompress(message))
                    return stats
                elif data:
                    raise ValueError("Invalid value in FIFO")
                else:
                    continue
            else:
                tries += 1
                logger.debug("Select timeout: retrying")
                if tries > 5:
                    logger.debug("Could not get statistic for flow generation")
                    return

    def read_flow_from_pipe(self):
        logger.debug("Getting flow statistic for generation")
        #msg = read_all_msg(self.pipeout)
        msg = self.reader.read()
        if msg:
            logger.debug("Read message of size %d", len(msg))
            stats = pickle.loads(zlib.decompress(msg))
            return stats
        else:
            raise ValueError("Invalid message from pipe")

    def finish_request(self, request, client_address):
        logger.debug("Received UDP request: %s", client_address)
        #s  = self.get_flow_stats()
        s = self.read_flow_from_pipe()

        if s is not None:
            logger.debug("#Loc_pkt: %d, #Rem_pkt: %d for client %s",
                         s.nbr_pkt, s.rem_nbr_pkt,
                         client_address)
            self.RequestHandlerClass(request, client_address, self, s.arr_gen,
                                     s.pkt_gen, s.first, s.rem_first,
                                     s.nbr_pkt, s.rem_nbr_pkt)

    def shutdown(self):
        #os.close(self.pipeout)
        self.reader.close()
        self.join()
        #os.remove(self.pipename)
        SocketServer.UDPServer.shutdown(self)

if __name__ == "__main__":
    server = None
    if proto == "tcp":
    # instantiate the server, and bind to localhost on port 9999
        if args.pipe:
            server = FlowTCPServer((ip, port), args.pipe, pipename=args.pipename)
        else:
            server = FlowTCPServer((ip, port), args.pipe, sock_ip=args.sock_ip,
                                   sock_port=args.sock_port)
    elif proto == "udp":
        if args.pipe:
            server = FlowUDPServer((ip, port), args.pipe, pipename=args.pipename)
        else:
            server = FlowUDPServer((ip, port), args.pipe, sock_ip=args.sock_ip,
                                   sock_port=args.sock_port)
    # activate the server
    # this will keep running until Ctrl-C
    if server:
        logger.debug("Starting Server %s:%s (%s)", ip, port, proto)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            server.shutdown()
            sys.exit(0)
