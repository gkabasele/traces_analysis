#!/usr/bin/python
from logging.handlers import RotatingFileHandler
import os
import logging
import socket
import sys
import argparse
import time
import string
import pickle
import random
import struct
import tempfile
import select


parser = argparse.ArgumentParser()
parser.add_argument("--saddr", type=str, dest="s_addr", action="store", help="source address")
parser.add_argument("--daddr", type=str, dest="d_addr", action="store", help="destination address")
parser.add_argument("--sport", type=int, dest="sport", action="store", help="source port of the client")
parser.add_argument("--dport", type=int, dest="dport", action="store", help="destination port of the server")
parser.add_argument("--dur", type=float, dest="duration", action="store", help="duration of the flow")
parser.add_argument("--size", type=int, dest="size", action="store", help="size of the flow")
parser.add_argument("--nbr", type=int, dest="nb_pkt", action="store", help="number_packet send in this flow")
parser.add_argument("--proto", type=str, dest="proto", action="store", help="protocol used for the flow")
args = parser.parse_args()


s_addr = args.s_addr
d_addr = args.d_addr
sport = args.sport
dport = args.dport
duration = args.duration
size = args.size
nb_pkt = args.nb_pkt
proto = args.proto

ALPHA = list(string.printable)

def create_chunk(size):
    s = ""
    for x in range(size):
        s+= ALPHA[random.randint(0, len(ALPHA)-1)]
    return bytes(s.encode("utf-8"))

def init_logger(ip):                                                                                           
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)
    formatter = logging.Formatter('%(asctime)s :: %(levelname)s :: %(message)s')
    logname = '../logs/client_%s.log' % (ip)
    if os.path.exists(logname):
        os.remove(logname)
    file_handler = RotatingFileHandler(logname, 'a', 1000000, 1)
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
    return logger

class FlowClient(object):

    """
        This class represent a client sending request to the server to get request
        - duration in second
        - size in byte
    """

    def __init__(self, client_ip, client_port, server_ip, server_port, duration,
                 size, nb_pkt, TCP=True, arr_dist=None, pkt_dist=None,
                 first=None, rem_arr_dist=None, rem_first=None):

        self.is_tcp = TCP

        if self.is_tcp:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        else:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.setblocking(0)

        self.server_ip = server_ip
        self.server_port = server_port
        self.client_ip = client_ip
        self.client_port = client_port
        self.duration = duration
        self.size = size
        self.nb_pkt = nb_pkt
        self.arr_dist = arr_dist
        self.pkt_dist = pkt_dist
        self.first = first
        self.rem_arr_dist = rem_arr_dist
        self.rem_first = rem_first



    def __str__(self):
        return "{}:{}".format(self.client_ip, self.client_port)

    def __repr__(self):
        return self.__str__()

    def retrieve_distribution(self, name):
        # TODO Read pip to retrieve distribution
        pass
    # The following methods are needed to have a better managment of the TCP packet size
    def _send_msg(self, msg):
        # Prefix each message with a 4-byte length (network byte order)
        msg = struct.pack('>I', len(msg)) + msg
        self.sock.sendall(msg)
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
            packet = self.sock.recv(n - len(data))
            if not packet:
                return None
            data += packet
        return data

    def generate_flow(self):
        #local index
        i = 0
        #remote index
        j = 0
        
        cur_pkt_ts = self.first
        rem_cur_pkt_ts = self.rem_first

        error = True
        try:
            self.sock.bind((self.client_ip, self.client_port))
            self.sock.connect((self.server_ip, self.server_port))

            while i < len(self.pkt_dist): 
                ts_next = cur_pkt_ts + self.arr_dist[i]
                rem_ts_next = rem_cur_pkt_ts + self.rem_arr_dist[j] 
                cur_waiting = self.arr_dist[i]

                if self.is_tcp:

                    if ts_next < rem_ts_next:
                        msg = create_chunk(self.pkt_dist[i])
                        time.sleep(cur_waiting)
                        self._send_msg(msg)
                        cur_pkt_ts = ts_next
                        i += 1

                    timeout = abs(cur_pkt_ts - rem_cur_pkt_ts)
                    ready = select.select([self.sock], [], [], timeout)
                    if ready[0]:
                        data = self._recv_msg()
                        rem_cur_pkt_ts = rem_ts_next
                        j += 1
                    else:
                        pass
                else:
                    #TODO UDP
                    pass
        except socket.error as msg:
            print("Unable to connect to the server %s" % msg)
        finally:
            if error:
                print("The flow generated does no match the requirement")
            self.sock.close()


    def run(self):
        recv_size = 0
        i = 0
        chunk_size = int(self.size/self.nb_pkt)
        error = True
        created_file = False
        #logger = init_logger(self.client_ip)
        try:
            # connect to server
            self.sock.bind((self.client_ip, self.client_port))
            self.sock.connect((self.server_ip, self.server_port))

            #print("Connected to the server")
            #logger.debug("client (%s) connected to server (%s)", self.client_ip,
            #             self.server_ip)
            data = pickle.dumps((self.duration, self.size, self.nb_pkt))
            #logger.debug("Request for a flow of size %s, duration %s and %s packets",
            #             self.size, self.duration, self.nb_pkt)
            self.sock.sendall(data)
            tmpdir = tempfile.gettempdir()
            file_name = (tmpdir + "/" + str(self.client_ip) + "_" +
                         str(self.client_port) + ".tmp")
            tmpf = open(file_name, 'w+')
            created_file = True
            #logger.debug("Temp file: %s", file_name)
            while recv_size < self.size:

                if self.is_tcp:
                    # receive data back from the server
                    received = self._recv_msg()
                    recv_size += len(received) + 4 # for the length field
                    i += 1
                else:
                    received, srv = self.sock.recvfrom(2*chunk_size)
                    recv_size += len(received)
                    i += 1

                #print("Packet recv: {}".format(i))
                #print("Size: {}/{}".format(recv_size, self.size))
            error = False
            #print("Done")
            #logger.debug("Finished receiving data")

        except socket.error as msg:
            #print("Unable to connect to the server %s" % msg)
            #logger.debug("Unable to connect to server %s: %s", msg, self.server_ip)
            pass
        finally:
            if error:
                pass
                #logger.debug("An error occurred")
            self.sock.close()
            if created_file:
                tmpf.close()
                os.remove(file_name)


if __name__ == "__main__":

    client = FlowClient(s_addr, sport, d_addr, dport, duration, size, nb_pkt, proto == "tcp")
    client.run()
