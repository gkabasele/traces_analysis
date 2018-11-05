import logging
import sys
import socketserver
import argparse
import cPickleas pickle
import random
import string

logging.basicConfig(level=logging.DEBUG,
        format='%(nmae)s:%(message)s',)

parser = argparse.ArgumentParser()
parser.add_argument("--addr", type=str, dest="ip", action="store", help="ip address of the host")
parser.add_argument("--port", type=int, dest="port", action="store", help="port of the service")
parser.add_argument("--proto", type=str, dest="tcp", action="store", help="protocol used for the flow")
args = parser.parse_args()

port = args.port
ip = args.ip
tcp = args.tcp



class FlowRequestHandler(socketserver.BaseRequestHandler):
    """
    The RequestHandler class for our server.

    It is instantiated once per connection to the server, and must
    override the handle() method to implement communication to the
    client.
    """
    ALPHA = list(string.printable)

    def __init__(self, request, client_address, server, TCP=True ):
        self.logger = logging.getLogger('FlowRequestHandler')
        self.logger.debug('__init__')
        if TCP:
            socketserver.TCPRequestHandler.__init__(self, request, client_address,
                                                    server) 
        else:
            socketserver.UDPRequestHandler.__init__(self, request, client_address,
                                                    server)
        self.size = None
        self.duration = None
        self.nb_pkt = None


    @classmethod
    def create_chunk(cls, size):
        s = ""
        for x in range(size):
            s += cls.ALPHA[random.randint(0, len(cls.ALPHA)-1)]  

        return bytes(s) 


    def handle(self):
        #If initial request compute retrieve chunk size
         
        data = pickle.load(self.request.recv())
        self.duration, self.size, self.nb_pkt = data
       
        chunk_size = self.size/self.nb_pkt 
        sended_size = 0

        while sended_size < size:
            self.request.sendall(FlowRequestHandler.create_chunk(chunk_size))
            # wait based on duration
            sended_size += chunk_size
        
class FlowServer(socketsever.BaseServer):

    def __init__(self, server_address,
                 TCP=True,
                 handler_class=FlowRequestHandler,):
        self.logger = logging.getLogger('FlowServer')
        self.logger.debug('__init__')
        self.is_tcp = TCP
        if TCP:
            socketserver.TCPServer.__init__(self, server_address, 
                                            handler_class)
        else:
            socketserver.UDPServer.__init__(self, server_address,
                                            handler_class)

    def finish_request(self, request, client_address):
        self.RequestHandlerClass(request, client_address, self, is_tcp)
        

if __name__ == "__main__":
                 
    
    # instantiate the server, and bind to localhost on port 9999
    server = FlowServer((ip, port),tcp == "tcp" ,FlowRequestHandler)
    
    # activate the server
    # this will keep running until Ctrl-C
    server.serve_forever()
