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
from threading import Thread
from traceback import format_exception
from util import Sender, Receiver
from util import read_all_msg
import flowDAO

parser = argparse.ArgumentParser()
parser.add_argument("--saddr", type=str, dest="s_addr", action="store", help="source address")
parser.add_argument("--daddr", type=str, dest="d_addr", action="store", help="destination address")
parser.add_argument("--sport", type=int, dest="sport", action="store", help="source port of the client")
parser.add_argument("--dport", type=int, dest="dport", action="store", help="destination port of the server")
parser.add_argument("--proto", type=str, dest="proto", action="store", help="protocol used for the flow")
group = parser.add_mutually_exclusive_group(required=True)
group.add_argument("--pipe", type=str, dest="pipe", action="store", help="name of pipe")
group.add_argument("--sock", type=int, dest="sock", action="store")

args = parser.parse_args()

s_addr = args.s_addr
d_addr = args.d_addr
sport = args.sport
dport = args.dport
proto = args.proto
if args.pipe:
    pipe = args.pipe
    pipe_entry = True
else:
    sock = args.sock
    pipe_entry = False

TIMEOUT = 1000

READ_ONLY = select.POLLIN | select.POLLPRI | select.POLLHUP | select.POLLERR

def create_chunk(size):
    return os.urandom(size)

def init_logger(ip):                                                                        
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)
    formatter = logging.Formatter('%(asctime)s :: %(levelname)s :: %(message)s')
    logname = '../logs/client_%s:%d:%s.log' % (ip, sport, proto)
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

        self.client_ip = client_ip
        self.client_port = client_port

        self.server_ip = server_ip
        self.server_port = server_port

        self.arr_gen = arr_gen
        self.pkt_gen = pkt_gen
        self.nbr_pkt = nbr_pkt
        self.first = first
        self.rem_first = rem_first
        self.rem_nbr_pkt = rem_nbr_pkt

        self.rlock = Lock()
        self.slock = Lock()
        # Remote ip -> (Number to receive, currently received)
        self.recv_ks = {}
        self.handlers = []

        self.one_connection_open = False

        logger.debug("Initializing pipe")

        if not os.path.exists(pipeinname):
            #os.mkfifo(pipeinname)
            raise ValueError("Pipe {} does not exist".format(pipeinname))

        #self.pipeout = os.open(pipeinname, os.O_NONBLOCK|os.O_RDONLY)
        self.pipeout = os.open(pipeinname, os.O_RDONLY)
        self.pipename = pipeinname
        logger.debug("Client Intialized")

    def listen_pipe(self):
        while True:
            readable, writable, exceptional = select.select([self.pipeout],
                                                            [],
                                                            [],
                                                            0.1)
            if readable:
                t_flow = Thread(target=self.handle_flow, args=())
                self.handlers.append(t_flow)
                if not self.one_connection_open:
                    t_sock = Thread(target=self.listen_sock, args=())
                    t_sock.start()
                    self.one_connection_open = True
                t_flow.start()

            if self.one_connection_open and not [x for x in self.handlers if x.is_alive()]:
                self.one_connection_open = False
                break

    def listen_sock(self):
        try:
            while True:
                readable, writable, exceptional = select.select([self.sock],
                                                                [],
                                                                [],
                                                                0.1)
                if readable:
                    self.slock.acquire()
                    if self.is_tcp():
                        data, addr = self._recv_msg()
                    else:
                        data, addr = self.sock.recvfrom(4096)

                    if data:
                        ip, port = addr
                        flowproto = 6 if self.is_tcp else 17
                        key = ":".join([ip, port, flowproto])
                        try:
                            self.rlock.acquire()
                            self.recv_ks[key][1] += 1
                            rem_nbr_pkt, cur_recv = self.recv_ks[key]
                            logger.debug("Pkt %d of %d bytes recv from %s",
                                         cur_recv, len(data), addr)
                            self.rlock.release()
                        except KeyError:
                            self.rlock.release()
                            logger.debug("Could not find %s", key)
                    self.slock.release()

                if not (readable or writable or exceptional):
                    pass

                if not self.one_connection_open:
                    break

        except socket.timeout:
            logger.debug("Socket operation has timeout")
        except socket.error as msg:
            logger.debug("Socket error: %s", msg)

    def handle_flow(self):
        flow = self.read_flow_gen_from_pipe()
        if flow is None:
            return

        res = self.connect_to_server(self.client_ip, self.client_port,
                                     flow.rem_ip, flow.rem_port, flow.proto)
        if res != 0:
            return

        key = ":".join([flow.rem_ip, flow.rem_port, flow.proto])

        self.recv_ks[key] = (flow.rem_nbr_pkt, 0)

        receiver = self.create_receiver(flow.rem_nbr_pkt, flow.rem_ip,
                                        flow.rem_port, flow.rem_proto,
                                        self.recv_ks)

        sender = self.create_sender(flow.first, flow.rem_first, flow.nbr_pkt, flow.arr_gen,
                                    flow.pkt_gen, flow.rem_ip, flow.rem_port)

        receiver.start()
        sender.start()

        receiver.join()
        sender.join()

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
        raw_msglen, addr = self._recvall(4)
        if not raw_msglen:
            return None
        msglen = struct.unpack('>I', raw_msglen)[0]
        return self._recvall(msglen)

    def _recvall(self, n):
        data = b''
        addr = None
        while len(data) < n:
            packet, addr = self.sock.recvfrom(n - len(data))
            if not packet:
                return None
            data += packet
        return data, addr

    def _send_msg_udp(self, msg, ip, port):
        self.sock.sendto(msg, (ip, port))
        return len(msg)

    def _recv_msg_udp(self, size):
        return self.sock.recvfrom(size)

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
                return gen
            else:
                raise ValueError("Error while unpickling  message from pipe")
        else:
            raise ValueError("Invalid message from pipe")


    def create_receiver(self, rem_nbr_pkt, ip, port, proto, recv_ks):

        receiver = Receiver("", rem_nbr_pkt, ip, port, proto, recv_ks, self.rlock,
                            logger)
        return receiver

    def connect_to_server(self, ip, port, rem_ip, rem_port, proto):
        try:
            logger.debug("Binding to socket")
            self.sock.bind((ip, port))
            logger.debug("Attempting connection to server")
            if proto == 6:
                self.sock.connect((rem_ip, rem_port))
                logger.debug("Connected to TCP server")
            else:
                logger.debug("Connected to UDP server")

            return 0
        except socket.error as err:
            logger.debug("Unable to connect to server: %s", err)
            return


    def create_sender(self, cur_pkt_ts, rem_cur_pkt_ts, nbr_pkt, arr_gen, pkt_gen,
                      rem_ip, rem_port):
        first_arr = 0
        if rem_cur_pkt_ts and cur_pkt_ts > rem_cur_pkt_ts:
            first_arr = cur_pkt_ts - rem_cur_pkt_ts

        sender = Sender("", nbr_pkt, arr_gen, pkt_gen, first_arr, self.sock,
                        self.slock, logger, rem_ip, rem_port, self.is_tcp)
        return sender


    def generate_flow_threaded(self):
        res = self.read_flow_gen_from_pipe()

        if res is None:
            return

        self._get_flow_generator(res.pkt_gen, res.arr_gen, res.first,
                                 res.rem_first, res.nbr_pkt, res.rem_nbr_pkt)

        logger.debug("#Loc_pkt: %s, #Rem_pkt: %s to server %s:%s",
                     self.nbr_pkt, self.rem_nbr_pkt, self.server_ip,
                     self.server_port)

        # remote index
        j = 0
        error = True
        flowproto = 6 if self.is_tcp else 17
        res = self.connect_to_server(self.client_ip, self.client_port,
                                     self.server_ip, self.server_port,
                                     flowproto)
        if res is None:
            return

        try:
            sender = self.create_sender(self.first, self.rem_first,
                                        self.nbr_pkt, self.arr_gen,
                                        self.pkt_gen, self.server_ip,
                                        self.server_port)
            sender.start()
            while j < self.rem_nbr_pkt:
                readable, writable, exceptional = select.select([self.sock],
                                                                [],
                                                                [self.sock],
                                                                0.1)
                if exceptional:
                    logger.debug("Error on select")
                if readable:
                    self.slock.acquire()
                    if self.is_tcp:
                        data, addr = self._recv_msg()
                    else:
                        data, addr = self.sock.recvfrom(4096)

                    if data:
                        logger.debug("Pkt %d/%d of %d bytes recv from %s:%s",
                                     j, self.rem_nbr_pkt, len(data),
                                     self.server_ip, self.server_port)
                        j += 1
                    self.slock.release()
                if not (readable or writable or exceptional):
                    pass

            logger.debug("All packet %d have been received from %s:%s", j,
                         self.server_ip, self.server_port)
            if sender.is_alive():
                sender.join()
            error = False

        except socket.timeout:
            logger.debug("Socket operation has timeout")

        except socket.error as msg:
            logger.debug("Socket error: %s", msg)

        finally:
            if error:
                logger.debug("The flow generated does no match the requirement")

    def finish(self):
        os.close(self.pipeout)
        #os.remove(self.pipename)
        #if self.is_tcp:
        #    self.sock.shutdown(socket.SHUT_RDWR)
        self.sock.close()

if __name__ == "__main__":

    client = FlowClient(s_addr, sport, d_addr, dport, pipe, proto == "tcp")
    client.generate_flow_threaded()
    client.finish()
