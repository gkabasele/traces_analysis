#!/usr/bin/python
import os
import sys
import logging
from logging.handlers import RotatingFileHandler
import SocketServer
import threading
import multiprocessing
import socket
import argparse
import cPickle as pickle
import random
import select
import struct
import time
import Queue
import zlib
from traceback import format_exception
from traceback import print_exc
from util import Sender
from util import read_all_msg
import flowDAO


logging.basicConfig(level=logging.DEBUG,
                    format='%(name)s:%(message)s',)

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


class ThreadPoolMixin:

    # Size of pool
    pool_size = 5

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

    def __init__(self, request, client_address, server, arr_gen=None,
                 pkt_gen=None, first=None, rem_first=None, nbr_pkt=None,
                 rem_nbr_pkt=None):

        self.pkt_gen = pkt_gen
        self.arr_gen = arr_gen
        self.first = first
        self.rem_first = rem_first
        self.nbr_pkt = nbr_pkt
        self.rem_nbr_pkt = rem_nbr_pkt
        SocketServer.StreamRequestHandler.__init__(self, request, client_address, server)

        logger.debug("Initialization of the TCP Handler")

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

    def handle(self):
        j = 0
        cur_pkt_ts = self.first
        rem_cur_pkt_ts = self.rem_first
        error = True
        try:
            first_arr = 0
            if rem_cur_pkt_ts and cur_pkt_ts > rem_cur_pkt_ts:
                first_arr = rem_cur_pkt_ts - cur_pkt_ts

            sender = Sender("", self.nbr_pkt, self.arr_gen,
                            self.pkt_gen, first_arr, self.request, self.server.lock, logger,
                            self.client_address[0], self.client_address[1], True)

            sender.start()
            while j < self.rem_nbr_pkt:
                readable, writable, exceptional = select.select([self.request],
                                                                [],
                                                                [self.request],
                                                                0.1)
                if exceptional:
                    logger.debug("Error on select")
                if readable:
                    self.server.lock.acquire()
                    data = self._recv_msg()
                    if data:
                        logger.debug("Pkt %d/%d of %d bytes recv from %s",
                                     j+1, self.rem_nbr_pkt,
                                     len(data), self.client_address)
                        j += 1
                    self.server.lock.release()
                if not (readable or writable or exceptional):
                    pass
            logger.debug("All packet %d have been received from %s ", j,
                         self.client_address)
            if sender.is_alive():
                sender.join()
            error = False

        except socket.error as msg:
            logger.debug("Socket error: %s", msg)
        except Exception:
            self.server.lock.release()
            logger.exception(print_exc())
        finally:
            if error:
                logger.debug("The flow generated does not match the requirement")
            try:
                self.server.lock.release()
            except threading.ThreadError:
                pass

class FlowTCPServer(ThreadPoolMixin, SocketServer.TCPServer):

    def __init__(self, server_address, is_pipe_entry, pipename=None, ip=None,
                 port=None,handler_class=TCPFlowRequestHandler):

        logger.debug("Initializing TCP server")
        ThreadPoolMixin.__init__(self)
        SocketServer.TCPServer.__init__(self, server_address, handler_class)

        if is_pipe_entry:
            logger.debug("Initializing pipe")
            if not os.path.exists(pipename):
                logger.debug("Pipe %s does not exist", pipename)
                raise ValueError("Pipe {} does not exist".format(pipename))
            self.reader = flowDAO.FlowRequestPipeReader(pipename)
        else:
            logger.debug("Initializing socket")
            self.reader = flowDAO.FlowRequestSockReader(ip, port)
            self.reader.start()
        self.lock = threading.Lock()
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
            readable, _, _ = select.select([self.reader.entry_point], [], [], 1)
            if readable:
                logger.debug("Reading pipe")
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
                if tries > 5:
                    logger.debug("Could not get statistic for flow generation")
                    return

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
        logger.debug("Received Request from %s", client_address)
        #s = self.get_flow_stats()
        s = self.read_flow_gen_from_pipe()

        if s is not None:

            logger.debug("#Loc_pkt: %d, #Rem_pkt: %d to client %s",
                         s.nbr_pkt,
                         s.rem_nbr_pkt,
                         client_address)

            self.RequestHandlerClass(request, client_address, self, s.arr_gen,
                                     s.pkt_gen, s.first, s.rem_first,
                                     s.nbr_pkt, s.rem_nbr_pkt)

    def shutdown(self):
        self.reader.close()
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
        try:
            first_arr = 0
            if rem_cur_pkt_ts and cur_pkt_ts > rem_cur_pkt_ts:
                first_arr = cur_pkt_ts - rem_cur_pkt_ts

            sender = Sender("", self.nbr_pkt, self.arr_gen,
                            self.pkt_gen, first_arr,
                            self.request[1], self.server.lock, logger,
                            self.client_address[0], self.client_address[1],
                            False)
            sender.start()
            while j < self.rem_nbr_pkt:
                readable, writable, exceptional = select.select([self.request[1]],
                                                                [],
                                                                [self.request[1]],
                                                                0.1)
                if exceptional:
                    logger.debug("Error on select")
                if readable:
                    self.server.lock.acquire()
                    data = self._recv_msg()
                    if data:
                        logger.debug("Pkt %d/%d of %d bytes recv from %s",
                                     j, self.rem_nbr_pkt, len(data),
                                     self.client_address)
                    j += 1
                    self.server.lock.release()
                if not (readable or writable or exceptional):
                    pass

            logger.debug("All packet %d have been received from %s", j,
                         self.client_address)
            if sender.is_alive():
                sender.join()
            error = False

        except socket.error as msg:
            logger.debug("Socket error: %s", msg)
        except Exception:
            logger.exception(print_exc())
        finally:
            if error:
                logger.debug("The flow generated does not match the requirement")

    def finish_request(self):
        logger.debug("flow generated for %s", self.client_address)

class FlowUDPServer(ThreadPoolMixin, SocketServer.UDPServer):

    def __init__(self, server_address, is_pipe_entry, pipename=None, ip=None, port=None,
                 handler_class=UDPFlowRequestHandler):

        logger.debug("Initializing UDP server")
        ThreadPoolMixin.__init__(self)
        SocketServer.UDPServer.__init__(self, server_address, handler_class)

        if is_pipe_entry:
            logger.debug("Initializing pipe")
            if not os.path.exists(pipename):
                logger.debug("Pipe %s does not exist", pipename)
                raise ValueError("Pipe {} does not exist".format(pipename))
            self.reader = flowDAO.FlowRequestPipeReader(pipename)
        else:
            logger.debug("Initializing socket")
            self.reader = flowDAO.FlowRequestSockReader(ip, port)
            self.reader.start()

        self.lock = threading.Lock()
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
            server = FlowTCPServer((ip, port), args.pipe, ip=args.sock_ip,
                                   port=args.sock_port)
    elif proto == "udp":
        if args.pipe:
            server = FlowUDPServer((ip, port), args.pipe, pipename=args.pipename)
        else:
            server = FlowUDPServer((ip, port), args.pipe, ip=args.sock_ip,
                                   port=args.sock_port)
    # activate the server
    # this will keep running until Ctrl-C
    if server:
        logger.debug("Starting Server %s:%s (%s)", ip, port, proto)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            server.shutdown()
            sys.exit(0)
