import os
import cPickle as pickle
import sys
import socket
import Queue
from abc import ABCMeta, abstractmethod
import util

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

        FlowDAOReader.__init__(os.open(pipename, os.O_RDONLY))

    def read(self):
        return util.read_all_msg(self.entry_point)

    def close(self):
        os.close(self.entry_point)

class FlowRequestPipeWriter(FlowDAOWriter):
    def __init__(self, pipename):

        FlowDAOWriter.__init__(os.open(pipename, os.O_WRONLY))

    def write(self, msg):
        return util.write_message(msg, self.entry_point)

    def close(self):
        os.close(self.entry_point)

class FlowRequestSockWriter(FlowDAOWriter):

    def __init__(self, ip, port, lock):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.lock = lock
        FlowDAOWriter.__init__(sock)
        try:
            self.entry_point.connect((ip, port))
        except socket.error as err:
            print err
            return

    def write(self, msg):
        self.lock.acquire()
        written = util.send_msg_tcp(self.entry_point, msg)
        self.lock.release()
        return written

    def close(self):
        self.entry_point.close()

class FlowRequestSockReader(FlowDAOReader):

    def __init__(self, ip, port):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.settimeout(60)
        FlowDAOReader.__init__(sock)
        self.queue = Queue.Queue()
        self.entry_point.bind(ip, port)
        self.stop = False

    def start(self):
        self.stop = True
        while self.stop:
            self.entry_point.listen()
            conn, addr = self.entry_point.accept()
            with conn:
                data = util.recv_msg_tcp(self.entry_point)
                self.queue.put(data)

    def read(self):
        return self.queue.get()

    def close(self):
        self.entry_point.close()
