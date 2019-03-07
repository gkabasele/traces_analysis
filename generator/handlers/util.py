import sys
import time
import datetime
import math
import struct
import os
import errno
import select
from collections import Counter
from threading import Thread
from threading import Timer
import numpy as np
import scipy.stats as stats
from scipy.linalg import norm
from scipy.spatial.distance import euclidean

_SQRT2 = np.sqrt(2)

epoch = datetime.datetime.utcfromtimestamp(0)
class RepeatedTimer(object):

    """Repeat `function` every `interval` seconds."""

    def __init__(self, interval, function, *args, **kwargs):
        self._timer     = None
        self.interval   = interval
        self.function   = function
        self.args       = args
        self.kwargs     = kwargs
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
        readable, writable, exceptional = select.select([p],
                                                        [],
                                                        [],
                                                        1)
        if readable:
            msg = read_message(p)
            return msg

def write_to_pipe(msg, p):
    length = '{0:04d}'.format(len(msg))
    os.write(p, b'X')
    os.write(p, length.encode('utf-8'))
    os.write(p, msg)

def send_msg_tcp(socket, msg):
    msg = struct.pack('>I', len(msg)) + msg
    res = socket.sendall(msg)
    if not res:
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
    socket.sendto(msg, (ip, port))
    return len(msg)

def _recv_msg_udp(socket, size):
    data, addr = socket.recvfrom(size)
    return data

class Sender(Thread):
    def __init__(self, name, nbr_pkt, arr_gen, pkt_gen, first_arr, socket, lock,
                 logger,
                 ip,
                 port,
                 step=0.005,
                 tcp=True):
        Thread.__init__(self)
        self.name = name
        self.nbr_pkt = nbr_pkt
        self.arr_gen = arr_gen
        self.socket = socket
        self.step = step
        self.pkt_gen = pkt_gen
        self.ip = ip
        self.port = port
        self.lock = lock
        self.logger = logger
        self.first_arr = first_arr
        self.tcp = tcp

    def _generate_until(self):
        while True:
            gen_size = self.pkt_gen.generate(1)[0]
            if gen_size > 0:
                return gen_size

    def run(self):
        cur_time = time.time()
        wait = self.step
        cur_arr = self.first_arr
        if self.pkt_gen:
            cur_size = self._generate_until()
        index = 0
        while True:
            if index < self.nbr_pkt:
                send_time = cur_time + cur_arr
                diff = send_time - time.time()
                if diff <= 0:
                    msg = create_packet(cur_size)
                    self.lock.acquire()
                    if not self.tcp:
                        res = send_msg_udp(self.socket, msg, self.ip, self.port)
                    else:
                        res = send_msg_tcp(self.socket, msg)
                    cur_time = time.time()
                    self.logger.debug("Packet nbr %s of size %d sent to %s:%s",
                                      index + 1, res, self.ip, self.port)
                    cur_arr = self.arr_gen.generate(1)[0]/1000
                    cur_size = self._generate_until()
                    index += 1
                    self.lock.release()
                else:
                    time.sleep(diff)
            else:
                break
        self.logger.debug("All %d packets have been sent", index)


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
