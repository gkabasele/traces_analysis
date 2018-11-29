#!/usr/bin/python
from logging.handlers import RotatingFileHandler
import os
import logging
import socketserver
import threading
import socket
import argparse
import pickle
import random
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
args = parser.parse_args()

port = args.port
ip = args.ip
proto = args.proto

#logger = logging.getLogger()
#logger.setLevel(logging.INFO)
#formatter = logging.Formatter('%(asctime)s :: %(levelname)s :: %(message)s')
#logname = '../logs/server_%s.log' % (ip)
#if os.path.exists(logname):
#    os.remove(logname)
#
#file_handler = RotatingFileHandler(logname, 'a', 1000000, 1)
#file_handler.setLevel(logging.INFO)
#file_handler.setFormatter(formatter)
#logger.addHandler(file_handler)


class FlowRequestHandler(socketserver.BaseRequestHandler):
    """
    The RequestHandler class for our server.

    It is instantiated once per connection to the server, and must
    override the handle() method to implement communication to the
    client.
    """
    ALPHA = list(string.printable)

    def __init__(self, request, client_address, server, is_tcp, pkt_dist=None, arr_dist=None):

        self.is_tcp = is_tcp 
        self.size = None
        self.duration = None
        self.nb_pkt = None
        self.pkt_dist = pkt_dist
        self.arr_dist = arr_dist

        if self.is_tcp:
            socketserver.StreamRequestHandler.__init__(self, request, client_address,
                                                       server)
        else:
            socketserver.DatagramRequestHandler.__init__(self, request, client_address,
                                                         server)
    def _send_msg(self, msg):
        # Prefix each message with a 4-byte length (network byte order)
        msg = struct.pack('>I', len(msg)) + msg
        if self.is_tcp:
            self.request.sendall(msg)
        else:
            self.request[1].sendto(msg, self.client_address)

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
            packet = None
            if self.is_tcp:
                packet = self.request.recv(n - len(data))
            else:
                packet = self.request[1].recv(n - len(data))

            if not packet:
                return None
            data += packet
        return data


    @classmethod
    def create_chunk(cls, size):
        s = ""
        for x in range(size):
            s += cls.ALPHA[random.randint(0, len(cls.ALPHA)-1)]

        return bytes(s.encode("utf-8"))

    """
        Take a vector of size K of random values and return a vector of size K with sum equal to 1
    """
    def softmax(self, x):
        e_x = np.exp(x - np.max(x))
        return e_x / e_x.sum()

    def generate_values(self, size, min_val, max_val, total, _type=float):
        tmp = [random.uniform(min_val, max_val) for x in range(size)]
        s = sum(tmp)
        val = [x/s for x in tmp]
        res = [_type(total * x) for x in val]
        return res

    def fill_values(self, values, size):

        diff = size - sum(values)

        while diff > 0:
            i = random.randint(0, len(values)-1)
            values[i] += 1
            diff -= 1

    def handle(self):
        if self.is_tcp:
            data = pickle.loads(self.request.recv(1024))
        else:
            data = pickle.loads(self.request[0])
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
            pkt = self.generate_values(self.nb_pkt, chunk_size/2, chunk_size*2, total_size, int)
            self.fill_values(pkt, total_size)

        if self.arr_dist:
            arrival = self.arr_dist
        else:
            arrival = self.generate_values(self.nb_pkt-1, 0.0, self.duration/2, self.duration)

        i = 0
        pkt_sent = 0
        error = True
        try:
            while remaining_bytes > 0:
                send_size = min(pkt[i], remaining_bytes)
                ## Remove header
                data = FlowRequestHandler.create_chunk(send_size)
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
            if self.is_tcp:
                self.request.close()
            else:
                self.request[1].close()

class FlowTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):

    def __init__(self, server_address,
                 handler_class=FlowRequestHandler,
                 pkt_dist=None, arr_dist=None):

        socketserver.TCPServer.__init__(self, server_address,
                                        handler_class)

        self.pkt_dist = None
        self.arr_dist = None
        self.retrieve_distribution(pkt_dist, arr_dist)

        #logger.debug("Creating server: %s", self)

    def __str__(self):
        return "{}:{}".format(self.server_address[0], self.server_address[1])

    def __repr__(self):
        return self.__str__()

    def finish_request(self, request, client_address):
        self.RequestHandlerClass(request, client_address, self, True, self.pkt_dist, self.arr_dist)

    def retrieve_distribution(self, pkt_dist, arr_dist):
        # pkt_dist and arr_dist are filename with the distribution
        pass

class FlowUDPServer(socketserver.ThreadingMixIn, socketserver.UDPServer):

    def __init__(self, server_address,
                 handler_class=FlowRequestHandler,
                 pkt_dist=None, arr_dist=None):

        socketserver.UDPServer.__init__(self, server_address,
                                        handler_class)

        self.pkt_dist = None
        self.arr_dist = None
        self.retrieve_distribution(pkt_dist, arr_dist)

        #logger.debug("Creating server: %s", self)

    def __str__(self):
        return "{}:{}".format(self.server_address[0], self.server_address[1])

    def __repr__(self):
        return self.__str__()

    def finish_request(self, request, client_address):
        self.RequestHandlerClass(request, client_address, self, False, self.pkt_dist, self.arr_dist)

    def retrieve_distribution(self, pkt_dist, arr_dist):
        pass

if __name__ == "__main__":
                 
    server = None
    if proto == "tcp":
    # instantiate the server, and bind to localhost on port 9999
        server = FlowTCPServer((ip, port))
    elif proto == "udp":
        server = FlowUDPServer((ip, port)) 
    # activate the server
    # this will keep running until Ctrl-C
    if server:
        #logger.debug("Starting Server %s:%s (%s)", ip, port, proto)
        server.serve_forever()
