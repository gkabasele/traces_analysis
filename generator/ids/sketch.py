import random
import ipaddress
import struct
import numpy as np
import pdb
PRIME_NBR = ((2**61) - 1) 
MAX_PARAM = 10000

class Cell(object):

    def __init__(self, n):

        self.n_last = [] 
        self.n = n
        self.curr_val = 0
        self.estim_val = 0
        self.curr_prob = 0
        self.estim_prob = 0

    def add_counter(self):

        if self.n_last > self.n:
            self.n_last.pop(0)

        self.n_last.append(self.curr_val)

    def update(self, value):
        self.curr_val += value

    def clear(self):
        self.curr_val = 0
        self.estim_val = 0
        self.curr_prob = 0
        self.estim_prob = 0

class LMS(object):

    def __init__(self, n):

        self.weights = [random.random() for _ in range(n)]
        self.forecast = None
        self.alpha = None

    def estimate_next(self, n_last):
        x = np.array(self.weights).dot(np.array(n_last))

    def update_weight(self, observed, n_last):
        error = observed - self.forecast
        self.weights = self.weights + self.alpha * error * np.array(n_last)

    def update_alpha(self, n_last):
        x = np.array(n_last).dot(np.array(n_last))
        self.alpha = float(1/ (2*x))

class HashFunc(object):

    def __init__(self, prime_number, limit, n):

        self.p = prime_number
        self.alpha = random.randint(1, MAX_PARAM)
        self.beta = random.randint(0, MAX_PARAM)
        self.c = limit
        self.array = [Cell(n) for i in range(limit)] 

    def hash(self, key):
        return (((self.alpha*key + self.beta) % self.p) % self.c) + 1

    def update(self, key, value):
        # key are expected to be destination ip address
        # value are expected to be the number of syn received
        i = self.hash(key)
        self.array[i] = value

    def get(self, key):
        return self.array[self.hash(key)]

    def compute_distribution(self):
        curr_sum = 0
        estim_sum = 0
        for cell in self.array:
            curr_sum += cell.curr_val
            estim_sum += cell.estim_val

        for cell in self.array:
            if curr_sum != 0:
                cell.curr_prob = cell.curr_val/curr_sum

            if estim_sum != 0:
                cell.estim_prob = cell.estim_val/estim_sum

    def get_distributions(self):
        estim_dist = [cell.estim_prob for cell in self.array]
        curr_dist = [cell.curr_prob for cell in self.array]
        return estim_dist, curr_dist

class Sketch(object):

    def __init__(self, nrows, ncols, n):

        self.nrows = nrows
        self.ncols = ncols

        self.hashes = [HashFunc(PRIME_NBR, self.ncols, n) for i in range(nrows)]

    def update(self, key, value):
        for hash_f in self.hashes:
            hash_f.update(key, value)

class SketchIDS(object):

    def __init__(self, nrows, ncols, n_last, alpha, beta, period=1):
        self.nrows = nrows
        self.ncols = ncols
        self.n_last = n_last
        self.alpha = alpha
        self.beta = beta
        self.period = period

        self.sketch = Sketch(nrows, ncols, n_last)
        # nrows div value computed for each table
        self.div_ts = []
        # derivation timeseries 
        self.div_ts_prime = []

def compute_chi_square_divergence(distp, distq):

    if len(distp) != len(distq):
        raise ValueError('The distribution do not have the same size')

    div = 0
    for p, q in zip(distp, distq):
        if q != 0:
            div += ((p - q)**2)/q

def test_hash_func():
    limit = 100
    value_a = 5
    value_b = 7

    n = 5

    hash_f = HashFunc(PRIME_NBR, limit, n)
    ipa = ipaddress.ip_address(unicode("10.0.0.3"))
    ipb = ipaddress.ip_address(unicode("10.0.0.4"))
    key_a = struct.unpack("!I", ipa.packed)[0]
    key_b = struct.unpack("!I", ipb.packed)[0]
    hash_f.update(key_a, value_a)
    hash_f.update(key_b, value_b)

    assert hash_f.get(key_a) == value_a
    assert hash_f.get(key_b) == value_b
    assert hash_f.get(key_a) != value_b

test_hash_func()
