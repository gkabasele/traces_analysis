import sys
import time
import datetime
import math
import struct
import os
import errno
import socket
import select
import logging
from logging.handlers import RotatingFileHandler
import threading
from threading import Thread, ThreadError
from threading import Timer, RLock
from collections import Counter
from collections import deque
from traceback import print_exc
from multiprocessing import Process
import numpy as np
import scipy.stats as stats
from scipy.linalg import norm
from scipy.spatial.distance import euclidean

_SQRT2 = np.sqrt(2)

epoch = datetime.datetime.utcfromtimestamp(0)
class RepeatedTimer(object):

    """Repeat `function` every `interval` seconds."""

    def __init__(self, interval, function, *args, **kwargs):
        self._timer = None
        self.interval = interval
        self.function = function
        self.args = args
        self.kwargs = kwargs
        self.is_running = False
        self.start()

    def _run(self):
        self.is_running = False
        self.start()
        self.function(*self.args, **self.kwargs)

    def start(self):
        if not self.is_running:
            self._timer = Timer(self.interval, self._run)
            self._timer.start()
            self.is_running = True

    def stop(self):
        self._timer.cancel()
        self.is_running = False

class TimedFuncException(Exception):

    def __init__(self, msg):
        self.msg = msg

class MaxAttemptException(TimedFuncException):
    pass

class TimedoutException(TimedFuncException):
    pass

class PipeLock(object):

    __slots__ = ['filelock', 'queuelock', 'waiting_thread']

    def __init__(self):
        self.filelock = RLock()
        self.queuelock = RLock()
        self.waiting_thread = deque()

    def add_thread(self, t):
        self.queuelock.acquire()
        self.waiting_thread.append(t)
        self.queuelock.release()

    def remove_thread(self):
        self.queuelock.acquire()
        self.waiting_thread.popleft()
        self.queuelock.release()

    def nbr_thread_waiting(self):
        return len(self.waiting_thread)

    def peek(self):
        return self.waiting_thread[0]

    def acquire(self):
        self.filelock.acquire()

    def release(self):
        self.filelock.release()

def create_packet(size):
    return os.urandom(int(size))

def write_message(p, msg):
    message = struct.pack('>I', len(msg)) + msg
    length = len(message)
    while length:
        try:
            sent = os.write(p, message)
        except OSError as e:
            if e == errno.EAGAIN:
                select.select([], [p], [])
                continue
            else:
                break    
        message = message[sent:]
        length -= sent

def _read_all(p, n):
    data = b''
    while len(data) < n:
        try:
            msg = os.read(p, n - len(data))
            if msg == "":
                break
            data += msg

        except OSError as e:
            if e == errno.EAGAIN:
                select.select([p], [], [])
            else:
                break
    return data

def read_message(p):
    raw_msglen = _read_all(p, 4)
    if not raw_msglen:
        return None
    msglen = struct.unpack('>I', raw_msglen)[0]
    return _read_all(p, msglen)

def read_all_msg(p):
    while True:
        readable, _, _ = select.select([p], [], [], 1)
        if readable:
            msg = read_message(p)
            return msg

def write_to_pipe(msg, p):
    length = '{0:04d}'.format(len(msg))
    os.write(p, b'X')
    os.write(p, length.encode('utf-8'))
    os.write(p, msg)

def send_msg_tcp(socket, data):
    msg = struct.pack('>I', len(data)) + data
    res = socket.sendall(msg)
    if res is None:
        return len(msg)

def _recvall(socket, n):
    data = b''
    while len(data) < n:
        packet = socket.recv(n - len(data))
        if not packet:
            return None
        data += packet
    return data

def recv_msg_tcp(socket):
    raw_msglen = _recvall(socket, 4)
    if not raw_msglen:
        return None
    msglen = struct.unpack('>I', raw_msglen)[0]
    return _recvall(socket, msglen)

def send_msg_udp(socket, msg, ip, port):
    sent = socket.sendto(msg, (ip, port))
    if sent == len(msg):
        return sent

def _recv_msg_udp(socket, size):
    data, _ = socket.recvfrom(size)
    return data

class Receiver(Thread):

    def __init__(self, name, rem_nbr_pkt, ip, port, proto, recv_ks, lock):
        Thread.__init__(self)
        self.name = name
        self.rem_nbr_pkt = rem_nbr_pkt
        self.ip = ip
        self.port = port
        self.recv_ks = recv_ks
        self.lock = lock
        self.key = ":".join([ip, port, proto])

    def run(self):
        j = self.rem_nbr_pkt
        while True:
            self.lock.acquire()
            j, nbr_recv = self.recv_ks[self.key]
            if j == nbr_recv:
                self.lock.release()
                break
            self.lock.release()

class Sender(Thread):
    def __init__(self, name, nbr_pkt, arr_gen, pkt_gen, first_arr, sock, lock,
                 ip,
                 port,
                 is_tcp,
                 logname,
                 step=0.005):
        Thread.__init__(self)
        self.name = name
        self.nbr_pkt = nbr_pkt
        self.arr_gen = arr_gen
        self.socket = sock
        self.step = step
        self.pkt_gen = pkt_gen
        self.ip = ip
        self.port = port
        self.lock = lock
        self.first_arr = first_arr
        self.is_tcp = is_tcp
        self.ps_index = 0
        self.ipt_index = 0
        self.logname = logname
        threading.currentThread().setName("-".join([name, "sender"]))

    def _generate_until(self):
        while True:
            gen_size = self.pkt_gen.generate(1)[0]
            if gen_size > 0:
                return gen_size

    def generate_ps(self):
        if self.ps_index < len(self.pkt_gen):
            ps = self.pkt_gen[self.ps_index]
            self.ps_index += 1
            return ps

    def generate_ipt(self):
        if self.ipt_index < len(self.arr_gen):
            ipt = self.arr_gen[self.ipt_index]
            self.ipt_index += 1
            return ipt/1000.0

    def run(self):
        logger = logging.getLogger()
        cur_time = time.time()
        cur_arr = self.first_arr/1000.0
        if len(self.pkt_gen) > 0:
            cur_size = self.generate_ps()
        index = 0
        try:
            while index < self.nbr_pkt:
                send_time = cur_time + cur_arr
                now = time.time()
                diff = send_time - now
                if diff <= 0:
                    msg = create_packet(cur_size)
                    _, writable, _ = select.select([], [self.socket], [], 1)
                    if writable:
                        self.lock.acquire()
                        if self.is_tcp:
                            res = send_msg_tcp(self.socket, msg)
                        else:
                            res = send_msg_udp(self.socket, msg, self.ip, self.port)
                        self.lock.release()
                        if res:
                            cur_time = time.time()
                            cur_arr = self.generate_ipt()
                            cur_size = self.generate_ps()
                            index += 1
                else:
                    time.sleep(diff)
            logger.debug("All %d packets have been sent to %s:%s",
                         self.nbr_pkt, self.ip, self.port)
        except socket.timeout:
            logger.debug("Socket operation has timeout")
        except socket.error as err:
            logger.debug("Socket error: %s", err)
        except Exception:
            logger.exception(print_exc())
        finally:
            # Release lock in case it was acquired before crashing
            try:
                self.lock.release()
            except ThreadError:
                pass
            except RuntimeError:
                pass
def get_pmf(data):
    C = Counter(data)
    total = float(sum(C.values()))
    for key in C:
        C[key] /= total
    return C


def compute_axis_scale(data):

    low = min(data)
    high = max(data)
    return (math.ceil(low-0.5*(high-low)), math.ceil(high+0.5*(high-low)))

def normalize_data(data):
    try:
        low = min(data)
        high = max(data)
        vrange = high - low
        if vrange == 0 :
            vrange = high
            if high == 0:
                return data 
        return [(x - low)/float(vrange) for x in data]
    except ZeroDivisionError:
        print data
        sys.exit()

def standardize_data(data):

    array = np.array(data)
    m = array.mean()
    s = array.std()

    return [x - m /float(s) for x in array]

def hellinger1(p, q):
    return norm(np.sqrt(p) - np.sqrt(q)) / _SQRT2

def hellinger2(p, q):
    return euclidean(np.sqrt(p), np.sqrt(q)) / _SQRT2

def hellinger3(p, q):
    return np.sqrt(np.sum((np.sqrt(p) - np.sqrt(q)) ** 2)) / _SQRT2

def distance_ks_mod(p, q):
    data1, data2 = map(np.asarray, (p, q))
    n1 = data1.shape[0]
    n2 = data2.shape[0]
    n1 = len(data1)
    n2 = len(data2)
    data1 = np.sort(data1)
    data2 = np.sort(data2)
    data_all = np.concatenate([data1, data2])
    cdf1 = np.searchsorted(data1, data_all, side='right')/(1.0*n1)
    cdf2 = np.searchsorted(data2, data_all, side='right')/(1.0*n2)
    d = np.average(np.absolute(cdf1-cdf2))
    en = np.sqrt(n1*n2/float(n1 + n2))
    return d

def distance_ks(p, q):
    return stats.ks_2samp(p, q)[0]

def datetime_to_ms(date):
    if date is not None:
        return (date - epoch).total_seconds() * 1000.0

def timeout_decorator(timeout=1, step=0.005, max_attempt=200):
    def decorator(func):
        def wrapper(*args, **kwargs):
            max_time = time.time() + timeout
            attempt = 0
            while True:
                if attempt >= max_attempt:
                    raise MaxAttemptException("%s/%s (try/apt)" % (attempt,
                                                                   max_attempt))
                value = func(*args, **kwargs)
                if value:
                    break
                else:
                    #attempt += 1
                    pass
                if time.time() >= max_time:
                    raise TimedoutException("Expected: %s, Got: %s" %
                                            (max_time, time.time()))
                time.sleep(step)
            return value
        return wrapper
    return decorator

def main():
    pass


if __name__ == "__main__":
    main()
