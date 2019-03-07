#!/usr/bin/python
import logging
from logging.handlers import RotatingFileHandler
import os
import socket
import sys
import argparse
import time
import cPickle as pickle
import struct
import select
import zlib
from threading import Lock
from traceback import format_exception
from util import Sender
from util import read_all_msg

parser = argparse.ArgumentParser()
parser.add_argument("--saddr", type=str, dest="s_addr", action="store", help="source address")
parser.add_argument("--daddr", type=str, dest="d_addr", action="store", help="destination address")
parser.add_argument("--sport", type=int, dest="sport", action="store", help="source port of the client")
parser.add_argument("--dport", type=int, dest="dport", action="store", help="destination port of the server")
parser.add_argument("--proto", type=str, dest="proto", action="store", help="protocol used for the flow")
parser.add_argument("--pipe", type=str, dest="pipe", action="store", help="name of pipe")

args = parser.parse_args()


s_addr = args.s_addr
d_addr = args.d_addr
sport = args.sport
dport = args.dport
proto = args.proto
pipe = args.pipe

TIMEOUT = 1000

READ_ONLY = select.POLLIN | select.POLLPRI | select.POLLHUP | select.POLLERR

def create_chunk(size):
    return os.urandom(size)

def init_logger(ip):                                                                        
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)
    formatter = logging.Formatter('%(asctime)s :: %(levelname)s :: %(message)s')
    logname = '../logs/client_%s:%d.log' % (ip, sport)
    if os.path.exists(logname):
        os.remove(logname)
    file_handler = RotatingFileHandler(logname, 'a', 1000000, 1)
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
    return logger

logger = init_logger(s_addr)

def log_exception(etype, val, tb):
    logger.exception("%s", "".join(format_exception(etype, val, tb)))

sys.excepthook = log_exception

class FlowClient(object):

    """
        This class represent a client sending request to the server to get request
        - duration in second
        - size in byte
    """

    def __init__(self, client_ip, client_port, server_ip, server_port,
                 pipeinname, TCP=True, arr_gen=None, pkt_gen=None,
                 first=None, rem_first=None, nbr_pkt=None, rem_nbr_pkt=None):

        logger.debug("Initializing Client")
        self.is_tcp = TCP

        if self.is_tcp:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        else:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        self.server_ip = server_ip
        self.server_port = server_port
        self.client_ip = client_ip
        self.client_port = client_port

        self.arr_gen = arr_gen
        self.pkt_gen = pkt_gen
        self.nbr_pkt = nbr_pkt
        self.first = first
        self.rem_first = rem_first
        self.rem_nbr_pkt = rem_nbr_pkt

        logger.debug("Initializing pipe")

        if not os.path.exists(pipeinname):
            os.mkfifo(pipeinname)

        self.pipeout = os.open(pipeinname, os.O_NONBLOCK|os.O_RDONLY)
        self.pipename = pipeinname
        logger.debug("Client Intialized")

    def __str__(self):
        return "{}:{}".format(self.client_ip, self.client_port)

    def __repr__(self):
        return self.__str__()

    # The following methods are needed to have a better managment of the TCP packet size
    def _send_msg(self, msg):
        # Prefix each message with a 4-byte length (network byte order)
        msg = struct.pack('>I', len(msg)) + msg
        res = self.sock.sendall(msg)
        if not res:
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

    def _send_msg_udp(self, msg, ip, port):
        self.sock.sendto(msg, (ip, port))
        return len(msg)

    def _recv_msg_udp(self, size):

        data, addr = self.sock.recvfrom(size)
        return data

    def _get_flow_generator(self, pkt_gen, arr_gen, first, rem_first, nbr_pkt,
                            rem_nbr_pkt):

        self.pkt_gen = pkt_gen
        self.arr_gen = arr_gen
        self.first = first
        self.rem_first = rem_first
        self.rem_nbr_pkt = rem_nbr_pkt
        self.nbr_pkt = nbr_pkt

    def read_flow_gen_from_pipe(self):
        logger.debug("Reading flow generator from pipe")
        msg = read_all_msg(self.pipeout)
        if msg:
            logger.debug("Read message of size %d", len(msg))
            gen = pickle.loads(zlib.decompress(msg))
            if gen:
                self._get_flow_generator(gen.pkt_gen, gen.arr_gen, gen.first,
                                         gen.rem_first, gen.nbr_pkt,
                                         gen.rem_nbr_pkt)
            return 0
        else:
            raise ValueError("Invalid message from pipe")

    def generate_flow_threaded(self):
        res = self.read_flow_gen_from_pipe()
        lock = Lock()

        if res is None:
            return

        logger.debug("#Loc_pkt: %s, #Rem_pkt: %s to server %s:%s",
                     self.nbr_pkt, self.rem_nbr_pkt, self.server_ip,
                     self.server_port)

        # local index
        i = 0
        # remote index
        j = 0

        cur_pkt_ts = self.first
        rem_cur_pkt_ts = self.rem_first

        error = True
        try:
            logger.debug("Binding to socket")
            self.sock.bind((self.client_ip, self.client_port))
            logger.debug("Attempting connection to server")
            if self.is_tcp:
                self.sock.connect((self.server_ip, self.server_port))
                logger.debug("Connected to TCP server")
            else:
                logger.debug("Connected to UDP server")
        except socket.error as e:
            logger.debug("Unable to connect to server: %s", e)
            return
        step = 0.005
        try:
            first_arr = 0
            if rem_cur_pkt_ts and cur_pkt_ts > rem_cur_pkt_ts:
                first_arr = cur_pkt_ts - rem_cur_pkt_ts

            sender = Sender(self.pipename, self.nbr_pkt, self.arr_gen,
                            self.pkt_gen, first_arr, self.sock, lock, logger,
                            self.server_ip, self.server_port,
                            tcp=self.is_tcp)

            sender.start()
            while True:
                if sender.is_alive() or j < self.rem_nbr_pkt:
                    if j < self.rem_nbr_pkt:
                        readable, writable, exceptional = select.select([self.sock],
                                                                        [],
                                                                        [self.sock],
                                                                        0.1)
                        if exceptional:
                            logger.debug("Error on select")
                        if readable:
                            lock.acquire()
                            if self.is_tcp:
                                data = self._recv_msg()
                            else:
                                data, addr = self.sock.recvfrom(4096)

                            if data:
                                logger.debug("Pkt %d of %d bytes recv from %s:%s",
                                             j, len(data), self.client_ip,
                                             self.client_port)
                                j += 1
                            lock.release()
                        if not (readable or writable or exceptional):
                            pass
                else:
                    break
                time.sleep(step)
            logger.debug("All packet %d have been received", j)
            if sender.is_alive():
                sender.join()
            error = False

        except socket.timeout as e:
            logger.debug("Socket operation has timeout")

        except socket.error as msg:
            logger.debug("Socket error: %s", msg)

        finally:
            if error:
                logger.debug("The flow generated does no match the requirement")

    def finish(self):
        os.close(self.pipeout)
        os.remove(self.pipename)
        self.sock.close()

if __name__ == "__main__":

    client = FlowClient(s_addr, sport, d_addr, dport, pipe, proto == "tcp")
    client.generate_flow_threaded()
    client.finish()
