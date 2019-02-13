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

logging.basicConfig(level=logging.DEBUG,
        format='%(nmae)s:%(message)s',)

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
logname = '../logs/server_%s.log' % (ip)
if os.path.exists(logname):
    os.remove(logname)

file_handler = RotatingFileHandler(logname, 'a', 1000000, 1)
file_handler.setLevel(logging.DEBUG)
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)

ALPHA = list(string.printable)

def create_chunk(size):
    #return os.urandom(size)
    s = ""
    for x in range(size):
        s += ALPHA[random.randint(0, len(ALPHA)-1)]
    
    return bytes(s.encode("utf-8"))

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

        i = 0
        j = 0

        cur_pkt_ts = self.first
        rem_cur_pkt_ts = self.rem_first
        error = True
        try:
            while i < len(self.pkt_dist) or j < len(self.rem_pkt_dist):
                if i < len(self.pkt_dist):
                    ts_next = cur_pkt_ts + self.arr_dist[i]
                    cur_waiting = self.arr_dist[i]

                if j < len(self.rem_arr_dist):
                    rem_ts_next = rem_cur_pkt_ts + self.rem_arr_dist[j]


                if (ts_next < rem_ts_next and i < len(self.pkt_dist) or
                        j >= len(self.rem_pkt_dist)):
                    msg = create_chunk(self.pkt_dist[i])
                    time.sleep(cur_waiting/1000.0)
                    self._send_msg(msg)
                    logger.debug("Sending packet")
                    cur_pkt_ts = ts_next
                    i += 1

                #timeout = abs(cur_pkt_ts - rem_cur_pkt_ts)
                #ready = select.select([self.rfile], [], [],
                #                      float(timeout)/1000)
                readable, writable, exceptional = select.select([self.request],
                                                                [],
                                                                [self.request], 1)
                if readable:
                    data = self._recv_msg()
                    if data:
                        logger.debug("Data recv: %d" % len(data))
                        logger.debug("Received packet")
                        rem_cur_pkt_ts = rem_ts_next
                        j += 1
                else:
                    rem_ts_next + 500
            error = False
        except socket.error as msg:
            logger.debug("Socket error" % msg)
        finally:
            if error:
                logger.debug("The flow genrated does not match the requirement")
            self.request.close()

        '''
        data = pickle.loads(self.request.recv(1024))
        self.duration, self.size, self.nb_pkt = data
        chunk_size = int(self.size/self.nb_pkt) - 4
        remaining_bytes = self.size

        #logger.debug("server received request from client %s",
        #             self.client_address)
        #logger.debug("Request for a flow of size %s, duration %s and %s packets",
        #             self.size, self.duration, self.nb_pkt)

        if self.pkt_dist:
            pkt = self.pkt_dist
        else:
            total_size = self.size - (4 * self.nb_pkt)
            pkt = generate_values(self.nb_pkt, chunk_size/2, chunk_size*2, total_size, int)
            fill_values(pkt, total_size)

        if self.arr_dist:
            arrival = self.arr_dist
        else:
            arrival = generate_values(self.nb_pkt-1, 0.0, self.duration/2, self.duration)

        i = 0
        pkt_sent = 0
        error = True
        try:
            while remaining_bytes > 0:
                send_size = min(pkt[i], remaining_bytes)
                ## Remove header
                data = create_chunk(send_size)
                send_size = self._send_msg(data)
                # wait based on duration
                remaining_bytes -= send_size
                pkt_sent += 1
                #logger.debug("Sending %s bytes of data", send_size)
                if i < len(arrival)-1:
                    time.sleep(arrival[i])
                i += 1
            error = False
            #logger.debug("Finished sending data")
        finally:
            if error:
                pass
                #logger.debug("An error occured")
            #self.request.close()
        '''
class FlowTCPServer(SocketServer.ThreadingMixIn, SocketServer.TCPServer):


    def __init__(self, server_address, pipeinname,
                 handler_class=TCPFlowRequestHandler):
        logger.debug("Initializing server")

        os.mkfifo(pipeinname)
        self.pipeout = os.open(pipeinname, os.O_NONBLOCK|os.O_RDONLY)
        #self.pipe = os.fdopen(pipeout, 'rb')
        SocketServer.TCPServer.__init__(self, server_address, handler_class)

        #logger.debug("Creating server: %s", self)

    def __str__(self):
        return "{}:{}".format(self.server_address[0], self.server_address[1])

    def __repr__(self):
        return self.__str__()


    def get_flow_stats(self, client_address):
        logger.debug("Getting flow statistic for generation")
        tries = 0
        while True:
            logger.debug("Select on pipe")
            readable, writable, exceptional = select.select([self.pipeout], [], [], 1)
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
        logger.debug("Received Request")
        s = self.get_flow_stats(client_address)

        if s is not None:
            logger.debug("#Loc_pkt: %d, #Rem_pkt: %d", len(s.pkt_dist),
                         len(s.rem_pkt_dist))
            self.RequestHandlerClass(request, client_address, self, s.pkt_dist,
                                     s.arr_dist, s.first, s.rem_arr_dist,
                                     s.rem_first, s.rem_pkt_dist)

    def shutdown(self):
        os.close(self.pipeout)
        SocketServer.TCPServer.shutdown(self)

class UDPFlowRequestHandler(SocketServer.BaseRequestHandler):

    def __init__(self, request, client_address, server, pkt_dist=None,
                 arr_dist=None,first=None, rem_arr_dist=None,
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
        self.request[1].setblocking(0)
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
            while i < len(self.pkt_dist) or j < len(self.rem_pkt_dist):
                if i < len(self.pkt_dist):
                    ts_next = cur_pkt_ts + self.arr_dist[i]
                    cur_waiting = self.arr_dist[i]

                if j < len(self.rem_arr_dist):
                    rem_ts_next = rem_cur_pkt_ts + self.rem_arr_dist[j]

                if (ts_next < rem_ts_next and i < len(self.pkt_dist) or
                        j >= len(self.rem_pkt_dist)):
                    msg = create_chunk(self.pkt_dist[i])
                    time.sleep(cur_waiting/1000.0)
                    self._send_msg(msg)
                    logger.debug("Sending packet")
                    cur_pkt_ts = ts_next
                    i += 1

                if first_pkt and self.request[0]:
                    logger.debug("Data recv: %d", len(self.request[0]))
                    logger.debug("Received packet")
                    rem_cur_pkt_ts = rem_ts_next
                    first_pkt = False
                    j += 1
                elif j < len(self.rem_pkt_dist):
                    readable, writable, exceptional = select.select([self.request[1]], [], [self.request], 1)

                    if exceptional:
                        logger.debug("Error on select")
                    if readable:
                        data = self._recv_msg()
                        if data:
                            logger.debug("Data recv: %d", len(data))
                            logger.debug("Received packet")
                            rem_cur_pkt_ts = rem_ts_next
                            j += 1
                    else:
                        logger.debug("Select time out")
            error = False
        except socket.error as msg:
            logger.debug("Socket error %s", msg)
        finally:
            if error:
                logger.debug("The flow genrated does not match the requirement")
            logger.debug("Loc pkt: %d, Rem pkt: %d", i, j)

    def finish_request(self):
        logger.debug("flow generated for %s", self.client_address)
        pass

class FlowUDPServer(SocketServer.ThreadingMixIn, SocketServer.UDPServer):

    def __init__(self, server_address, pipeinname,
                 handler_class=UDPFlowRequestHandler):

        logger.debug("Initializing UDP server")

        os.mkfifo(pipeinname)
        self.pipeout = os.open(pipeinname, os.O_NONBLOCK|os.O_RDONLY)

        SocketServer.UDPServer.__init__(self, server_address, handler_class)

        #logger.debug("Creating server: %s", self)

    def __str__(self):
        return "{}:{}".format(self.server_address[0], self.server_address[1])

    def __repr__(self):
        return self.__str__()

    def get_flow_stats(self, client_address):
        logger.debug("Getting flow statistic for generation")
        tries = 0
        while True:
            logger.debug("Select on pipe")
            ready = select.select([self.pipeout], [], [], 1)
            if ready[0]:
                logger.debug("Reading pipe")
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
                if tries > 5:
                    logger.debug("Could not get statistic for flow generation")
                    return
                else:
                    time.sleep(0.5)


    def finish_request(self, request, client_address):
        logger.debug("Received UDP request")
        s  = self.get_flow_stats(client_address)
        if s is not None:
            logger.debug("#Loc_pkt: %d, #Rem_pkt: %d", len(s.pkt_dist),
                         len(s.rem_pkt_dist))
            self.RequestHandlerClass(request, client_address, self, s.pkt_dist,
                                     s.arr_dist, s.first, s.rem_arr_dist,
                                     s.rem_first, s.rem_pkt_dist)


    def shutdown(self):
        os.close(self.pipeout)
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
        #logger.debug("Starting Server %s:%s (%s)", ip, port, proto)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            server.shutdown()
            sys.exit(0)