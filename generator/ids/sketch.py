import random
import struct
import os
import argparse
import re
import math
import pdb
from datetime import datetime, timedelta
import ipaddress
import numpy as np
import matplotlib.pyplot as plt

REG =r"(?P<ts>(\d+\.\d+)) IP (?P<src>(?:\d{1,3}\.){3}\d{1,3})(\.(?P<sport>\d+)){0,1} > (?P<dst>(?:\d{1,3}\.){3}\d{1,3})(\.(?P<dport>\d+)){0,1}: Flags (?P<flag>(?:\[\w*\.{0,1}]))"

REG_FLOW =r"(?P<ts>(\d+\.\d+)) IP (?P<src>(?:\d{1,3}\.){3}\d{1,3})(\.(?P<sport>\d+)){0,1} > (?P<dst>(?:\d{1,3}\.){3}\d{1,3})(\.(?P<dport>\d+)){0,1}: (?P<proto>(tcp|TCP|udp|UDP|icmp|ICMP))( |, length )(?P<size>\d+){0,1}"

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

    def __init__(self, n, weight_init=None):

        self.n_last = [] 
        self.n = n
        self.curr_val = 0
        self.estim_val = 0
        self.curr_prob = 0
        self.estim_prob = 0
        self.estimator = LMS(n, weight_init=weight_init)

    def add_counter(self):

        self.n_last.append(self.curr_val)

        if len(self.n_last) > self.n:
            self.n_last.pop(0)

    def update(self, value):
        self.curr_val += value

    def clear(self):
        self.curr_val = 0
        self.curr_prob = 0
        self.estim_prob = 0
        self.estim_val = 0

    def estimate(self):
        self.estimator.estimate_next(self.n_last)
        if self.estimator.forecast < 0:
            self.estimator.forecast = 0
        self.estim_val = self.estimator.forecast

    def update_estimator(self):
        self.estimator.compute_error(self.curr_val)
        self.estimator.update_mu(self.n_last)
        self.estimator.update_weight(self.n_last)

class LMS(object):

    RAND = 'random'
    ZERO = 'zero'

    def __init__(self, n, mu=0.001, weight_init=None):

        if weight_init == LMS.RAND or weight_init is None:
            self.weights = [random.random() for _ in range(n)]
        elif weight_init == LMS.ZERO:
            self.weights = np.zeros(n)
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
        if x != 0:
            self.mu = float(1)/(2*x)

class HashFunc(object):

    def __init__(self, prime_number, limit, n, coef_bound=3, coef_fore=0.7,
                 weight_init=None):

        self.p = prime_number
        self.alpha = random.randint(1, MAX_PARAM)
        self.beta = random.randint(0, MAX_PARAM)
        self.c = limit
        self.cells = [Cell(n, weight_init=weight_init) for _ in range(limit)]

        self.coef_bound = coef_bound
        self.coef_fore = coef_fore

        self.bound = None

        self.divergences = []
        self.filter_divergences = []
        self.div_mean = None
        self.div_std = None
        self.consecutive_exceed = 0

        self.thresholds = []

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
            if len(self.divergences) > 1:
                if self.divergences[-1] == self.filter_divergences[-1]:
                    cell.update_estimator()
            else:
                cell.update_estimator()

    def add_counter(self):
        for cell in self.cells:
            if len(self.divergences) > 1:
                if self.divergences[-1] == self.filter_divergences[-1]:
                    cell.add_counter()
            else:
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

    def get_non_zero_prob(self):
        curr_dist = [c.curr_prob for c in self.cells if c.curr_prob != 0]
        estim_dist = [c.estim_prob for c in self.cells if c.estim_prob != 0]
        return curr_dist, estim_dist

    def get_non_zero_val(self):
        curr_vals = [c.curr_val for c in self.cells if c.curr_val != 0]
        estim_vals = [c.estim_val for c in self.cells if c.estim_val != 0]
        return curr_vals, estim_vals

    def get_nlast(self):
        return [c.n_last for c in self.cells if 0 not in c.n_last]

    def compute_divergence(self, debug=False):
        div = 0
        for c in self.cells:
            p = c.curr_prob
            q = c.estim_prob
            if q != 0:
                div += ((p - q)**2)/float(q)
            if div < 0:
                pdb.set_trace()

        return div

    def adapt(self, debug=False):
        self.compute_distribution()
        if debug:
            pdb.set_trace()
        current = self.compute_divergence(debug)
        if len(self.divergences) < 2:
            self.filter_divergences.append(current)
            self.divergences.append(current)
            self.div_mean = np.mean(self.divergences)
            self.div_std = np.std(self.divergences)
            self.thresholds.append(self.div_mean + self.coef_bound *
                                   math.sqrt(self.div_std))
        else:
            if current < self.div_mean  + self.coef_bound * math.sqrt(self.div_std):
                self.filter_divergences.append(current)
                self.consecutive_exceed = 0
            else:
                #val = self.filter_divergences[random.randint(0,len(self.filter_divergences)-1)]
                #self.filter_divergences.append(val)
                self.filter_divergences.append(self.filter_divergences[-1])
                self.consecutive_exceed += 1

            last = self.filter_divergences[-2]
            last_filter = self.filter_divergences[-1]
            #self.div_mean = (self.coef_fore*self.div_mean +
            #                 (1 - self.coef_fore)*last)
            #self.div_std = (self.coef_fore*self.div_std +
            #                (1 - self.coef_fore)*(last_filter-self.div_mean)**2)

            self.div_mean = np.mean(self.filter_divergences[:-2])
            self.div_std = np.var(self.filter_divergences)

            self.divergences.append(current)
            self.thresholds.append(self.div_mean + self.coef_bound *
                                   math.sqrt(self.div_std))

    def alarm_decision(self, consecutive):
        return (self.divergences[-1] != self.filter_divergences[-1] and
                self.consecutive_exceed >= consecutive)

    def estimate_update_counter(self):
        for cell in self.cells:
            cell.estimate()
            if len(self.divergences) > 1:
                if self.divergences[-1] == self.filter_divergences[-1]:
                    cell.update_estimator()
                    cell.add_counter()
            else:
                cell.update_estimator()
                cell.add_counter()


class Sketch(object):

    EST = "estimate"
    UPDATE = "update"

    def __init__(self, nrows, ncols, n, weight_init=None):

        self.nrows = nrows
        self.ncols = ncols

        self.hashes = [HashFunc(PRIME_NBR, self.ncols, n, weight_init=weight_init) for _ in range(nrows)]

    def update(self, key, value):
        for hash_f in self.hashes:
            hash_f.update(key, value)

    def compute_divergences(self, debug=False):
        for hash_f in self.hashes:
            hash_f.adapt(debug)

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

    def estimate_update_counter(self):
        for hash_f in self.hashes:
            hash_f.estimate_update_counter()

    def clear(self):
        for hash_f in self.hashes:
            hash_f.clear_counter()

class SketchIDS(object):

    def __init__(self, reg, nrows, ncols, n_last, alpha, beta, 
                 training_period, thresh, consecutive, period=15,
                 quiet=False, weight_init=None):

        if n_last >= training_period:
            raise ValueError("Number of value considered cannot not be more than interval")

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

        self.sketch = Sketch(nrows, ncols, n_last, weight_init=weight_init)

        self.start = None
        self.end = None
        self.current_interval = 0
        self.mal_interval = []
        self.quiet = quiet

    def _getdata(self, line):
        try:
            res = self.reg.match(line)
            ts = datetime.fromtimestamp(float(res.group(TS)))
            src = ipaddress.ip_address(unicode(res.group(SRC)))
            dst = ipaddress.ip_address(unicode(res.group(DST)))
            sport = res.group(SPORT)
            dport = res.group(DPORT)
            #flag = res.group(FLAG)
            return ts, src, sport, dst, dport
        except AttributeError:
            pdb.set_trace()

    def run(self, dirname, debug=False):
        listdir = sorted(os.listdir(dirname))
        for trace in listdir:
            filename = os.path.join(dirname, trace)
            with open(filename, "r") as f:
                self.run_on_timeseries(f, debug)

    def run_on_timeseries(self, f, debug):
        for line in f:
            res = self._getdata(line)
            if not res:
                continue
            ts, _, _, dst, _ = res

            if self.start is None:
                self.start = ts
                self.end = ts + self.period
                #print("Starting Interval {}".format(self.current_interval))
                self.update_sketch(dst)
            else:
                if ts >= self.end:
                    self.run_detection(debug)

                    self.current_interval += 1
                    #print("Starting Interval {}".format(self.current_interval))
                    self.start = self.end
                    self.end = self.start + self.period
                    self.update_sketch(dst)
                else:
                    self.update_sketch(dst)

    def update_sketch(self, dip):
        key = struct.unpack("!I", dip.packed)[0]
        self.sketch.update(key, 1)

    def run_detection(self, debug=False):
        if self.current_interval < self.n_last:
            self.sketch.add_counter()
        elif self.current_interval < self.nbr_training:
            self.sketch.estimate_update_counter()
        else:
            self.sketch.estimate_counters()
            self.sketch.compute_divergences(debug)
            self.sketch.update_estimator()
            nbr_high_div = self.sketch.count_exceeding_div(self.cons)
            #Only update when there is no attack
            if nbr_high_div >= self.thresh:
                self.raise_alert()
            else:
                self.sketch.add_counter()
        self.sketch.clear()

    def raise_alert(self):
        if not self.quiet:
            print("Alert in interval {}".format(self.current_interval))
        self.mal_interval.append(self.current_interval)

    def dt_to_sec(self, dt):
        epoch = datetime.utcfromtimestamp(0)
        return (dt - epoch).total_seconds()

    def plot_divergences(self):
        for hash_f in self.sketch.hashes:
            div_mean = np.mean(hash_f.filter_divergences[:2])
            div_std = np.std(hash_f.filter_divergences[:2])
            threshold = [div_mean + self.alpha*div_std]
            for j in range(2, len(hash_f.filter_divergences)+1):
                div_mean = np.mean(hash_f.filter_divergences[:j-1])
                div_std = np.std(hash_f.filter_divergences[:j])
                threshold.append(div_mean + self.alpha * div_std)
            x_axis = np.arange(self.current_interval - self.nbr_training)
            plt.plot(x_axis, hash_f.divergences, label='div')
            plt.plot(x_axis, hash_f.filter_divergences, label='div_prime')
            plt.plot(x_axis, hash_f.thresholds, '-.', label='dyn_thresh')
            plt.plot(x_axis, threshold, '--', label='thresh')
            plt.legend(loc='upper right')
            plt.show()

def main(dirname):

    ids = SketchIDS(reg=re.compile(REG_FLOW), nrows=5, ncols=100, n_last=5,
                    alpha=4, beta=0.7, training_period=15, thresh=3,
                    consecutive=3, period=60)

    ids.run(dirname, debug=False)
    ids.plot_divergences()

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--indir", type=str, dest="indir")

    args = parser.parse_args()
    indir = args.indir
    main(indir)
