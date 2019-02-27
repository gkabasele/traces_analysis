import sys
import time
import datetime
import math
import struct
import os
import functools
import numpy as np
import scipy as sp
import scipy.stats as stats
from threading import Timer
from threading import Thread
from collections import Counter
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
    return os.urandom(size)

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
    def __init__(self, name, times, sizes, socket, lock, index, logger,
                 ip,
                 port,
                 step=0.005,
                 tcp=True):
        Thread.__init__(self)
        self.name = name
        self.times = times
        self.socket = socket
        self.step = step
        self.sizes = sizes
        self.ip = ip
        self.port = port
        self.lock = lock
        self.logger = logger
        self.index = index
        self.tcp = tcp

    def run(self):
        cur_time = time.time()
        wait = self.step
        while True:
            if self.index < len(self.times):
                send_time = cur_time + self.times[self.index]/1000
                diff = send_time - time.time()
                if diff <= 0:
                    msg = create_packet(self.sizes[self.index])
                    self.lock.acquire()
                    if not self.tcp:
                        res = send_msg_udp(self.socket, msg, self.ip, self.port)
                    else:
                        res = send_msg_tcp(self.socket, msg)
                    cur_time = time.time()
                    self.logger.debug("Packet nbr %s of size %d sent to %s:%s",
                                      self.index, res, self.ip, self.port)
                    self.index += 1
                    self.lock.release()
                    #diff = cur_time + self.times[self.index]/1000
                    #wait = diff if diff > 0 else 0
                else:
                    time.sleep(diff)
            else:
                break
        self.logger.debug("All packet have been sent")

def proposal_function(params, sigmas):
    res = []
    for i, val in enumerate(params):
        res.append(stats.norm(val,sigmas[i]).rvs(1))
    return res

def manual_log_lik_gamma(x, data):
    return np.sum((x[0]-1)*np.log(data) - (1/x[1])*data - x[0]*np.log(x[1]) - np.log(math.gamma(x[0])))

def log_lik_gamma(x, data):
    return np.sum(np.log(stats.gamma(a=x[0], scale=x[1],
                         loc=0).pdf(data)))

def log_lik_lomax(x,data):
    return np.sum(np.log(stats.lomax(c=x[0], scale=x[1],
                                     loc=0).pdf(data)))

def prior(w):
    if(w[0]<=0 or w[1] <= 0):
        return 0
    else:
        return 1

def acceptance(x, x_new):
    if x_new > x:
        return True
    else:
        accept = np.random.uniform(0, 1)
        return (accept <(np.exp(x_new-x)))


                  
def metroplolis_algorithm(likelihood_func, prior_func, transition_model,
                          param_init, iterations, data, acceptance_rule, sigmas):
    x = param_init
    accepted = []
    rejected = []
    for i in range(iterations):
        x_new = transition_model(x, sigmas)
        x_lik = likelihood_func(x, data)
        x_new_lik = likelihood_func(x_new, data)
        if (acceptance_rule(x_lik + np.log(prior_func(x)), x_new_lik +
                            np.log(prior_func(x_new)))):
            x = x_new
            accepted.append(x_new)
        else:
            rejected.append(x_new)
    return np.array(accepted), np.array(rejected)

def get_pmf(data):
    C = Counter(data)
    total = float(sum(C.values()))
    for key in C:
        C[key] /= total
    return C

def estimate_distribution(data, iterations, param_init , sigmas,dist="gamma"):

    if dist == "gamma":
        return metroplolis_algorithm(log_lik_gamma, prior,
                                     proposal_function, param_init, iterations,
                                     data, acceptance, sigmas)
    elif dist == "lomax":
        return metroplolis_algorithm(log_lik_lomax, prior,
                                     proposal_function, param_init, iterations,
                                     data, acceptance, sigmas)
def reject_accept(dist, nsample):
    # x are keys of the dict (pkt size)
    # y are val of the dict (frequence)

    x = dist.keys()
    y = dist.values()
    a = min(x)
    b = max(x)
    c = max([i/(1/float(len(y))) for i in y])    

    sample = []

    while len(sample) < nsample:
        proposal = stats.uniform(loc=a, scale=b).rvs(1)[0]
        q = c*1/len(x)
        if stats.uniform().rvs(1) <= (dist[proposal]/q):
            sample.append(proposal)
    return sample

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
