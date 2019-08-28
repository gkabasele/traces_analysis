import random
import struct
import os
import pdb
from datetime import datetime, timedelta 
import numpy as np
import ipaddress

REG =r"(?P<ts>(\d+\.\d+)) IP (?P<src>(?:\d{1,3}\.){3}\d{1,3})(\.(?P<sport>\d+)){0,1} > (?P<dst>(?:\d{1,3}\.){3}\d{1,3})(\.(?P<dport>\d+)){0,1}: Flags (?P<flag>\[\w*\.])"

example = "1557677026.750692 IP 10.0.0.2.55434 > 10.0.0.1.2499: Flags [S], seq 1066291379, win 29200, options [mss 1460,sackOK,TS val 790753459 ecr 0,nop,wscale 9], length 0"

TS = "ts"
SRC = "src"
SPORT = "sport"
DST = "dst"
DPORT = "dport"
PROTO = "proto"
SIZE = "size"
FLAG = "flag"

PRIME_NBR = ((2**61) - 1) 
MAX_PARAM = 10000

class Cell(object):

    # use to perform several method in one loop
    CLEAR = "clear"
    EST = "estimate"
    ADD = "add_counter"

    def __init__(self, n):

        self.n_last = [] 
        self.n = n
        self.curr_val = 0
        self.estim_val = 0
        self.curr_prob = 0
        self.estim_prob = 0
        self.estimator = LMS(n)

    def add_counter(self):

        if self.n_last > self.n:
            self.n_last.pop(0)

        self.n_last.append(self.curr_val)

    def update(self, value):
        self.curr_val += value

    def clear(self):
        self.curr_val = 0
        self.curr_prob = 0
        self.estim_prob = 0

    def estimate(self):
        self.estimator.estimate_next(self.n_last)
        self.estim_val = self.estimator.forecast

    def update_estimator(self):
        self.estimate()
        self.estimator.compute_error(self.curr_val)
        self.estimator.update_weight(self.n_last)

class LMS(object):

    def __init__(self, n, mu=0.1):

        self.weights = [random.random() for _ in range(n)]
        self.forecast = None
        self.mu = mu
        self.error = None

    def estimate_next(self, n_last):
        x = np.dot(self.weights, np.array(n_last))
        self.forecast = x

    def compute_error(self, observed):
        self.error = observed - self.forecast

    def update_weight(self, n_last):
        self.weights = self.weights + self.mu * self.error * np.array(n_last)

    def update_mu(self, n_last):
        x = np.array(n_last).dot(np.array(n_last))
        self.mu = float(1/ (2*x))

class HashFunc(object):

    def __init__(self, prime_number, limit, n, coef_bound=3, coef_fore=0.7):

        self.p = prime_number
        self.alpha = random.randint(1, MAX_PARAM)
        self.beta = random.randint(0, MAX_PARAM)
        self.c = limit
        self.cells = [Cell(n) for _ in range(limit)]

        self.coef_bound = coef_bound
        self.coef_fore = coef_fore

        self.bound = None

        self.divergences = []
        self.filter_divergences = []
        self.div_mean = None
        self.div_std = None
        self.consecutive_exceed = 0

    def hash(self, key):
        #should add + 1 in paper but index start at 0
        return (((self.alpha*key + self.beta) % self.p) % self.c)

    def update(self, key, value):
        # key are expected to be destination ip address
        # value are expected to be the number of syn received
        i = self.hash(key)
        self.cells[i].update(value) 

    def get(self, key):
        return self.cells[self.hash(key)].curr_val

    def clear_counter(self):
        for cell in self.cells:
            cell.clear()

    def estimate_counter(self):
        for cell in self.cells:
            cell.estimate()

    def update_estimator(self):
        for cell in self.cells:
            cell.update_estimator()

    def add_counter(self):
        for cell in self.cells:
            cell.add_counter()

    def compute_distribution(self):
        curr_sum = 0
        estim_sum = 0
        for cell in self.cells:
            curr_sum += cell.curr_val
            estim_sum += cell.estim_val

        i = 0
        for cell in self.cells:
            if curr_sum != 0:
                cell.curr_prob = float(cell.curr_val)/curr_sum
                i += 1

            if estim_sum != 0:
                cell.estim_prob = float(cell.estim_val)/estim_sum

    def compute_divergence(self):
        div = 0
        for c in self.cells:
            p = c.curr_prob
            q = c.estim_prob
            if q != 0:
                div += ((p -q)**2)/float(q)
        return div

    def update_mean_std(self):
        self.compute_distribution()
        current = self.compute_divergence()
        if self.div_mean is None and self.div_std is None:
            self.div_mean = current
            self.div_std = 0
            self.filter_divergences.append(current)
        else:
            if current < self.div_mean  + self.coef_bound * self.div_std:
                self.filter_divergences.append(current)
                self.consecutive_exceed = 0
            else:
                self.filter_divergences.append(self.filter_divergences[-1])
                self.consecutive_exceed += 1

            last = self.divergences[-1]
            last_filter = self.filter_divergences[-1]
            self.div_mean = self.coef_fore*self.div_mean + (1 - self.coef_fore)*last
            self.div_std = (self.coef_fore*self.div_std +
                            (1 - self.coef_fore)*(last_filter-self.div_mean)**2)

        self.divergences.append(current)
    def alarm_decision(self, consecutive):
        return (self.divergences[-1] != self.filter_divergences[-1] and
                self.consecutive_exceed >= consecutive)

class Sketch(object):

    def __init__(self, nrows, ncols, n):

        self.nrows = nrows
        self.ncols = ncols

        self.hashes = [HashFunc(PRIME_NBR, self.ncols, n) for _ in range(nrows)]

    def update(self, key, value):
        for hash_f in self.hashes:
            hash_f.update(key, value)

    def compute_divergences(self):
        for hash_f in self.hashes:
            hash_f.update_mean_std()

    def count_exceeding_div(self, consecutive):
        count = 0
        for hash_f in self.hashes:
            if hash_f.alarm_decision(consecutive):
                count += 1
        return count

    def add_counter(self):
        for hash_f in self.hashes:
            hash_f.add_counter()

    def estimate_counters(self):
        for hash_f in self.hashes:
            hash_f.estimate_counter()

    def update_estimator(self):
        for hash_f in self.hashes:
            hash_f.update_estimator()

class SketchIDS(object):

    def __init__(self, reg, nrows, ncols, n_last, alpha, beta, 
                 training_period, thresh, consecutive, period=60):

        self.reg = reg

        # IDS params
        self.nrows = nrows
        self.ncols = ncols
        self.n_last = n_last
        self.alpha = alpha
        self.beta = beta
        self.period = timedelta(seconds=period)
        self.cons = consecutive
        self.thresh = thresh
        self.nbr_training = training_period

        self.sketch = Sketch(nrows, ncols, n_last)

        self.start = None
        self.end = None
        self.current_interval = 0

    def _getdata(self, line):
        res = self.reg.math(line)
        ts = datetime.fromtimestamp(float(res.group(TS)))
        src = res.group(SRC)
        dst = res.group(DST)
        sport = res.group(SPORT)
        dport = res.group(DPORT)
        flag = res.group(FLAG)
        return ts, src, sport, dst, dport, flag

    def run(self, dirname, nb_inter):
        listdir = sorted(os.listdir(dirname))
        for trace in listdir:
            filename = os.path.join(dirname, trace)
            with open(filename, "r") as f:
                self.run_on_timeseries(f)

    def run_on_timeseries(self, f):
        for line in f:
            res = self._getdata(line)
            if not res:
                continue
            ts, src, sport, dst, dport, flag = res

            if self.start is None:
                self.start = ts
                self.end = ts + self.period
            else:
                if ts >= self.end:

                    self.run_detection(ts, src, sport, dst, dport,)

                    self.current_interval += 1
                    self.start = self.end
                    self.end = self.start + self.period
                    if flag == "[S]":
                        self.update_sketch(dst)
                else:
                    if flag == "[S]":
                        self.update_sketch(dst)

    def update_sketch(self, dip):
        self.sketch.update(dip, 1)

    def run_detection(self, ts, src, sport, dst, dport):
        if self.current_interval == 0:
            self.sketch.add_counter()
        elif self.current_interval < self.nbr_training:
            self.sketch.add_counter()
            self.sketch.update_estimator()
        else:
            self.sketch.compute_divergences()
            nbr_high_div = self.sketch.count_exceeding_div(self.cons)
            #Only update when there is no attack
            if nbr_high_div >= self.thresh:
                self.raise_alert()
            else:
                self.sketch.update_estimator()
                self.sketch.add_counter()

    def raise_alert(self):
        print("Alert in interveal {}".format(self.current_interval))
