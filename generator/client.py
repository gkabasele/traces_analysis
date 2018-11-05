# echo_client.py

import socket
import sys
import argparse
import time
import cPickle as pickle


parser = argparse.ArgumentParser()
parser.add_argument("--addr", type=str, dest="ip", action="store", help="ip address of the host")
parser.add_argument("--port", type=int, dest="port", action="store", help="port of the service")
parser.add_argument("--dur", type=int, dest="duration", action="store", help="duration of the flow")
parser.add_argument("--size", type=int, dest="size", action="store", help="size of the flow")
parser.add_argument("--nbr", type=int, dest="nb_pkt", action="store", help="number_packet send in this flow")
parser.add_argument("--proto", type=str, dest="tcp", action="store", help="protocol used for the flow")
args = parser.parse_args()


port = args.port
ip = args.ip
duration = args.duration
size = args.size
tcp = args.tcp


class FlowClient(object):

    """
        This class represent a client sending request to the server to get request
        - duration in second
        - size in byte
    """

    def __init__(self, server_ip, server_port, duration, size, nb_pkt, TCP=True):

        if TCP :
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        else
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        self.ip = server_ip
        self.port = server_port
        self.duration = duration
        self.size = size
        self.nb_pkt = nb_pkt

    def run(self):
        start = time.time()
        elasped_time = 0
        nbr_packet = 0
        recv_size = 0
        chunk_size = self.size/self.nb_pkt
        try:
            # connect to server 
            sock.connect((ip, port))
            data = pickle.dumps((self.duration, self.size, self.nb_pkt))
            sock.sendall(data)

            while recv_size < self.size:
                # receive data back from the server
                received = str(sock.recv(chunk_size))
                recv_size += self.size
        finally:
            # shut down
            sock.close()


if __name__ == "__main__":

    client = FlowClient(ip, port, duration, size, tcp == "tcp")) 
    client.run()

