import os
import cPickle as pickle
import sys
import socket
import Queue
from abc import ABCMeta, abstractmethod
import util
import threading
import traceback
import logging

logger = logging.getLogger()

class FlowDAOReader(object):

    __metaclass__ = ABCMeta

    def __init__(self, entry_point):

        self.entry_point = entry_point

    @abstractmethod
    def read(self):
        pass

    @abstractmethod
    def close(self):
        pass

class FlowDAOWriter(object):

    __metaclass__ = ABCMeta

    def __init__(self, entry_point):
        self.entry_point = entry_point

    @abstractmethod
    def write(self, msg):
        pass

    @abstractmethod
    def close(self):
        pass


class FlowRequestPipeReader(FlowDAOReader):

    def __init__(self, pipename):

        try:
            FlowDAOReader.__init__(self, os.open(pipename, os.O_RDONLY))
        except:
            logger.debug(traceback.format_exc())

    def read(self):
        return util.read_all_msg(self.entry_point)

    def close(self):
        os.close(self.entry_point)

class FlowRequestPipeWriter(FlowDAOWriter):
    def __init__(self, pipename):

        try:
            FlowDAOWriter.__init__(self, os.open(pipename, os.O_WRONLY))
        except:
            logger.debug(traceback.format_exc())

    def write(self, msg):
        return util.write_message(self.entry_point, msg)

    def close(self):
        os.close(self.entry_point)

class FlowRequestSockWriter(FlowDAOWriter):

    def __init__(self, ip, port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            FlowDAOWriter.__init__(self, sock)
            self.entry_point.connect((ip, port))
        except socket.error as err:
            print err
            return

    def write(self, msg):
        written = util.send_msg_tcp(self.entry_point, msg)
        return written

    def close(self):
        self.entry_point.close()

class FlowRequestSockReader(FlowDAOReader):

    def __init__(self, ip, port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.settimeout(60)
            FlowDAOReader.__init__(self, sock)
            self.queue = Queue.Queue()
            self.entry_point.bind((ip, port))
            self.running = False
            self.th = threading.Thread(target=self.handler, args=())
            self.th.setDaemon(1)
        except socket.error as err:
            print err
            return

    def start(self):
        self.th.start()

    def handler(self):
        self.running = True
        while self.running:
            try:
                self.entry_point.listen(3)
                conn, addr = self.entry_point.accept()
                data = util.recv_msg_tcp(conn)
                self.queue.put(data)
                conn.close()
            except socket.timeout:
                pass

    def read(self):
        return self.queue.get()

    def close(self):
        self.running = False
        self.th.join()
        self.entry_point.close()
