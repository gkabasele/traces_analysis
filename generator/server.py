#!/usr/bin/python
import logging
import sys
import socketserver
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

class FlowRequestHandler(socketserver.BaseRequestHandler):
    """
    The RequestHandler class for our server.

    It is instantiated once per connection to the server, and must
    override the handle() method to implement communication to the
    client.
    """
    ALPHA = list(string.printable)

    def __init__(self, request, client_address, server, is_tcp):

        self.is_tcp = is_tcp 
        self.size = None
        self.duration = None
        self.nb_pkt = None

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
            self.request[1].sendto(msg, (self.client_address))

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

    def generate_values(self, size, min_val, max_val, total):
        tmp = [random.uniform(min_val, max_val) for x in range(size)]
        s = sum(tmp)
        val = [x/s for x in tmp ]
        res = [total * x for x in val] 
        return res
        
    def handle(self):
        if self.is_tcp:
            data = pickle.loads(self.request.recv(1024))
        else:
            data = pickle.loads(self.request[0])
        self.duration, self.size, self.nb_pkt = data
       
        chunk_size = int(self.size/self.nb_pkt) - 4 
        remaining_bytes = self.size 

        int_pkt = int(self.duration/self.nb_pkt)
        arrival = self.generate_values(self.nb_pkt-1, 0.0, self.duration/2, self.duration)
        print("Chunk Size Pkt: {}".format(chunk_size))
        print("Arrival:{} Sum:{} Len:{}".format(arrival, sum(arrival), len(arrival)))

        i = 0
        while remaining_bytes > 0:
            send_size = min(chunk_size, remaining_bytes)
            ## Remove header
            data = FlowRequestHandler.create_chunk(send_size)
            send_size = self._send_msg(data)
            # wait based on duration
            remaining_bytes -= send_size
            print("Sending {} bytes of data".format(send_size))
            print("Remaining bytes: {}".format(remaining_bytes))
            if i < len(arrival)-1:
                time.sleep(arrival[i])
                i += 1
        
class FlowTCPServer(socketserver.TCPServer):

    def __init__(self, server_address,
                 handler_class=FlowRequestHandler,):

        socketserver.TCPServer.__init__(self, server_address, 
                                            handler_class)

    def finish_request(self, request, client_address):
        self.RequestHandlerClass(request, client_address, self, True)

class FlowUDPServer(socketserver.UDPServer):

    def __init__(self, server_address,
                 handler_class=FlowRequestHandler,):
        socketserver.UDPServer.__init__(self, server_address,
                                        handler_class)

    def finish_request(self, request, client_address):
        self.RequestHandlerClass(request, client_address, self, False)
        

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
        server.serve_forever()
