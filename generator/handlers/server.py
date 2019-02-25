#!/usr/bin/python
from logging.handlers import RotatingFileHandler
import os
import sys
import logging
import SocketServer
import threading
import socket
import argparse
import pickle
import random
import select
import string
import struct
import time
import numpy as np
from util import Sender
from traceback import format_exception
from traceback import print_exc

logging.basicConfig(level=logging.DEBUG,
        format='%(name)s:%(message)s',)

parser = argparse.ArgumentParser()
parser.add_argument("--addr", type=str, dest="ip", action="store", help="ip address of the host")
parser.add_argument("--port", type=int, dest="port", action="store", help="port of the service")
parser.add_argument("--proto", type=str, dest="proto", action="store", help="protocol used for the flow")
parser.add_argument("--pipe", type=str, dest="pipe", action="store", help="named pipe")

args = parser.parse_args()

port = args.port
ip = args.ip
proto = args.proto
pipe = args.pipe

logger = logging.getLogger()
logger.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s :: %(levelname)s :: %(message)s')
logname = '../logs/server_%s:%d.log' % (ip, port)
if os.path.exists(logname):
    os.remove(logname)

file_handler = RotatingFileHandler(logname, 'a', 1000000, 1)
file_handler.setLevel(logging.DEBUG)
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)

def create_chunk(size):
    return os.urandom(size)

def generate_values(size, min_val, max_val, total, _type=float):
    tmp = [random.uniform(min_val, max_val) for x in range(size)]
    s = sum(tmp)
    val = [x/s for x in tmp]
    res = [_type(total * x) for x in val]
    return res

def fill_values(values, size):
    diff = size - sum(values)

    while diff > 0:
        i = random.randint(0, len(values)-1)
        values[i] += 1
        diff -= 1

def log_exception(etype, val, tb):
    logger.exception("%s", "".join(format_exception(etype, val, tb)))

sys.excepthook = log_exception

class TCPFlowRequestHandler(SocketServer.StreamRequestHandler):
    """
    The RequestHandler class for our server.

    It is instantiated once per connection to the server, and must
    override the handle() method to implement communication to the
    client.
    """

    def __init__(self, request, client_address, server, pkt_dist, arr_dist,
                 first, rem_arr_dist, rem_first, rem_pkt_dist):

        self.pkt_dist = pkt_dist
        self.arr_dist = arr_dist
        self.first = first
        self.rem_arr_dist = rem_arr_dist
        self.rem_first = rem_first
        self.rem_pkt_dist = rem_pkt_dist
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
        lock = threading.Lock()

        i = 0
        j = 0
        cur_pkt_ts = self.first
        rem_cur_pkt_ts = self.rem_first
        error = True
        step = 0.005
        try:
            times = None
            if rem_cur_pkt_ts is None or cur_pkt_ts < rem_cur_pkt_ts:
                times = self.arr_dist
            else:
                first_ipt = rem_cur_pkt_ts - cur_pkt_ts
                self.arr_dist[0] = first_ipt
                times = self.arr_dist

            sender = Sender(self.server.pipename, times, self.pkt_dist,
                            self.request, lock, i, logger)  
            sender.start()
            while True:
                if sender.is_alive() or j < len(self.rem_pkt_dist):
                    if j < len(self.rem_pkt_dist):
                        readable, writable, exceptional = select.select([self.request],
                                                                        [],
                                                                        [self.request],
                                                                        0.005)
                        if exceptional:
                            logger.debug("Error on select")
                        if readable:
                            lock.acquire()
                            data = self._recv_msg()
                            logger.debug("Data recv: %d", len(data))
                            j += 1
                            lock.release()
                        if not (readable or writable or exceptional):
                            logger.debug("Select timeout")
                else:
                    break
                time.sleep(step)
            sender.join()
            error = False

        except socket.error as msg:
            logger.debug("Socket error: %s", msg)
        except Exception as e:
            logger.exception(print_exc())
        finally:
            if error:
                logger.debug("The flow generated does not match the requirement")

            logger.debug("Loc pkt: %d, Rem pkt: %d for client: %s", i, j,
                         self.client_address)


    def handle_mod(self):

        i = 0
        j = 0

        cur_pkt_ts = self.first
        rem_cur_pkt_ts = self.rem_first
        error = True
        try:
            diff = 0.0
            while i < len(self.pkt_dist) or j < len(self.rem_pkt_dist):
                if i < len(self.pkt_dist):
                    ts_next = cur_pkt_ts + self.arr_dist[i]
                    tmp = self.arr_dist[i]/1000.0 - diff
                    if tmp > 0:
                        cur_waiting = tmp
                    else:
                        cur_waiting = 0

                if j < len(self.rem_arr_dist):
                    rem_ts_next = rem_cur_pkt_ts + self.rem_arr_dist[j]

                if ((j >= len(self.rem_pkt_dist)) or
                        (i < len(self.pkt_dist) and ts_next < rem_ts_next)):
                    msg = create_chunk(self.pkt_dist[i])
                    before_waiting = time.time()
                    send_time = before_waiting + cur_waiting
                    time.sleep(cur_waiting)
                    diff = abs((time.time() - send_time))
                    self._send_msg(msg)
                    logger.debug("Sending packet to %s", self.client_address)
                    cur_pkt_ts = ts_next
                    i += 1

                readable, writable, exceptional = select.select([self.request],
                                                                [],
                                                                [self.request],
                                                                0.005)
                if exceptional:
                    logger.debug("Error on select")
                if readable:
                    data = self._recv_msg()
                    if data:
                        logger.debug("Data recv: %d from %s", len(data),
                                     self.client_address)
                        rem_cur_pkt_ts = rem_ts_next
                        j += 1
                if not (readable or writable or exceptional):
                    logger.debug("Select timeout")

            error = False
        except socket.error as msg:
            logger.debug("Socket error" % msg)
        except Exception as e:
            logger.exception(print_exc())
        finally:
            if error:
                logger.debug("The flow generated does not match the requirement")

            logger.debug("Loc pkt: %d, Rem pkt: %d for client: %s", i, j,
                         self.client_address)

class FlowTCPServer(SocketServer.ThreadingMixIn, SocketServer.TCPServer):


    def __init__(self, server_address, pipeinname,
                 handler_class=TCPFlowRequestHandler):
        logger.debug("Initializing server")

        if not os.path.exists(pipeinname):
            os.mkfifo(pipeinname)

        self.pipeout = os.open(pipeinname, os.O_NONBLOCK|os.O_RDONLY)
        self.pipename = pipeinname
        SocketServer.TCPServer.__init__(self, server_address, handler_class)

        logger.debug("Server initialized")

    def __str__(self):
        return "{}:{}".format(self.server_address[0], self.server_address[1])

    def __repr__(self):
        return self.__str__()


    def get_flow_stats(self, client_address):
        logger.debug("Getting flow statistic for generation")
        tries = 0
        while True:
            logger.debug("Select on pipe")
            readable, writable, exceptional = select.select([self.pipeout], [], [], 3)
            if exceptional:
                logger.debug("Error on select")
            if readable:
                logger.debug("Reading pipe")
                data = os.read(self.pipeout,1)
                if data == 'X':
                    raw_length = os.read(self.pipeout, 4)
                    message = os.read(self.pipeout, int(raw_length))
                    stats = pickle.loads(message)
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
                else:
                    time.sleep(0.5)

    def finish_request(self, request, client_address):
        logger.debug("Received Request from %s", client_address)
        s = self.get_flow_stats(client_address)

        if s is not None:
            logger.debug("#Loc_pkt: %d, #Rem_pkt: %d", len(s.pkt_dist),
                         len(s.rem_pkt_dist))
            self.RequestHandlerClass(request, client_address, self, s.pkt_dist,
                                     s.arr_dist, s.first, s.rem_arr_dist,
                                     s.rem_first, s.rem_pkt_dist)

    def shutdown(self):
        os.close(self.pipeout)
        os.remove(self.pipename)
        SocketServer.TCPServer.shutdown(self)

class UDPFlowRequestHandler(SocketServer.BaseRequestHandler):

    def __init__(self, request, client_address, server, pkt_dist=None,
                 arr_dist=None, first=None, rem_arr_dist=None,
                 rem_first=None, rem_pkt_dist=None):

        self.size = None
        self.duration = None
        self.nb_pkt = None
        self.pkt_dist = pkt_dist
        self.arr_dist = arr_dist
        self.first = first
        self.rem_pkt_dist = rem_pkt_dist
        self.rem_arr_dist = rem_arr_dist
        self.rem_first = rem_first

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
        data, addr =  self.request[1].recvfrom(4096)
        return data

    def _recvall(self, n):
        data = b''
        while len(data) < n:
            packet, addr = self.request[1].recvfrom(n - len(data))[0]
            if not packet:
                return None
            data += packet
        return data

    def handle(self):
        i = 0
        j = 0

        cur_pkt_ts = self.first
        rem_cur_pkt_ts = self.rem_first
        error = True
        first_pkt = True
        try:
            diff = 0.0
            while i < len(self.pkt_dist) or j < len(self.rem_pkt_dist):
                if i < len(self.pkt_dist):
                    ts_next = cur_pkt_ts + self.arr_dist[i]
                    tmp = self.arr_dist[i]/1000.0 - diff
                    if tmp > 0:
                        cur_waiting = tmp
                    else:
                        cur_waiting = 0

                if j < len(self.rem_arr_dist):
                    rem_ts_next = rem_cur_pkt_ts + self.rem_arr_dist[j]

                if ((j>= len(self.rem_pkt_dist)) or 
                        (i < len(self.pkt_dist) and ts_next < rem_ts_next)):
                    msg = create_chunk(self.pkt_dist[i])
                    before_waiting = time.time()
                    send_time = before_waiting + cur_waiting
                    time.sleep(cur_waiting)
                    diff = abs((time.time() - send_time))
                    self._send_msg(msg)
                    logger.debug("Sending packet to %s", self.client_address)
                    cur_pkt_ts = ts_next
                    i += 1
                    nb_select = 0

                if first_pkt and self.request[0]:
                    logger.debug("Data recv: %d from %s", len(self.request[0]),
                                 self.client_address)
                    rem_cur_pkt_ts = rem_ts_next
                    first_pkt = False
                    j += 1
                elif j < len(self.rem_pkt_dist):
                    readable, writable, exceptional = select.select([self.request[1]],
                                                                    [],
                                                                    [self.request],
                                                                    0.1)
                    if exceptional:
                        logger.debug("Error on select")
                    if readable:
                        data = self._recv_msg()
                        if data:
                            logger.debug("Data recv: %d", len(data))
                            logger.debug("Received packet")
                            rem_cur_pkt_ts = rem_ts_next
                            j += 1
                    if not (readable or writable or exceptional):
                        logger.debug("Select time out")
            error = False
        except socket.error as msg:
            logger.debug("Socket error %s", msg)
        except Exception as e:
            logger.exception(print_exc())
        finally:
            if error:
                logger.debug("The flow generated does not match the requirement")
            logger.debug("Loc pkt: %d, Rem pkt: %d for client: %s", i, j,
                         self.client_address)

    def finish_request(self):
        logger.debug("flow generated for %s", self.client_address)

class FlowUDPServer(SocketServer.ThreadingMixIn, SocketServer.UDPServer):

    def __init__(self, server_address, pipeinname,
                 handler_class=UDPFlowRequestHandler):

        logger.debug("Initializing UDP server")

        if not os.path.exists(pipeinname):
            os.mkfifo(pipeinname)

        self.pipeout = os.open(pipeinname, os.O_NONBLOCK|os.O_RDONLY)
        self.pipename = pipeinname

        SocketServer.UDPServer.__init__(self, server_address, handler_class)

        logger.debug("Server initialized")

    def __str__(self):
        return "{}:{}".format(self.server_address[0], self.server_address[1])

    def __repr__(self):
        return self.__str__()

    def get_flow_stats(self, client_address):
        logger.debug("Getting flow statistic for generation")
        tries = 0
        while True:
            logger.debug("Select on pipe")
            readable, writable, exceptional = select.select([self.pipeout], [], [], 3)
            if readable:
                data = os.read(self.pipeout, 1)
                if data == 'X':
                    raw_length = os.read(self.pipeout, 4)
                    message = os.read(self.pipeout, int(raw_length))
                    stats = pickle.loads(message)
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
                else:
                    time.sleep(0.5)


    def finish_request(self, request, client_address):
        logger.debug("Received UDP request: %s", client_address)
        s  = self.get_flow_stats(client_address)
        if s is not None:
            logger.debug("#Loc_pkt: %d, #Rem_pkt: %d", len(s.pkt_dist),
                         len(s.rem_pkt_dist))
            self.RequestHandlerClass(request, client_address, self, s.pkt_dist,
                                     s.arr_dist, s.first, s.rem_arr_dist,
                                     s.rem_first, s.rem_pkt_dist)

    def shutdown(self):
        os.close(self.pipeout)
        os.remove(self.pipename)
        SocketServer.UDPServer.shutdown(self)

if __name__ == "__main__":
    server = None
    if proto == "tcp":
    # instantiate the server, and bind to localhost on port 9999
        server = FlowTCPServer((ip, port), pipe)
    elif proto == "udp":
        server = FlowUDPServer((ip, port), pipe)
    # activate the server
    # this will keep running until Ctrl-C
    if server:
        logger.debug("Starting Server %s:%s (%s)", ip, port, proto)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            server.shutdown()
            sys.exit(0)
