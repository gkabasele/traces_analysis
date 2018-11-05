import logging
import sys
import socketserver
import socket
import argparse
import pickle
import random
import string

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

    def __init__(self, request, client_address, server, TCP=True ):
        if TCP:
            socketserver.StreamRequestHandler.__init__(self, request, client_address,
                                                    server) 
        else:
            socketserver.DataRequestHandler.__init__(self, request, client_address,
                                                    server)
        self.size = None
        self.duration = None
        self.nb_pkt = None


    @classmethod
    def create_chunk(cls, size):
        s = ""
        for x in range(size):
            s += cls.ALPHA[random.randint(0, len(cls.ALPHA)-1)]  

        return bytes(s.encode("utf-8")) 


    def handle(self):
        #If initial request compute retrieve chunk size
         
        data = pickle.loads(self.request.recv(1024))
        self.duration, self.size, self.nb_pkt = data
       
        chunk_size = int(self.size/self.nb_pkt)
        remaining_bytes = self.size 

        while remaining_bytes > 0:
            send_size = min(chunk_size, remaining_bytes)
            self.request.sendall(FlowRequestHandler.create_chunk(send_size))
            # wait based on duration
            remaining_bytes -= send_size
        
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
        self.ResquestHandlerClass(request, client_addrss, self, False)
        

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
