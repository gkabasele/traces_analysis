import re
import os
import math
import pdb
import argparse
from collections import OrderedDict
from datetime import datetime, timedelta
from scipy.stats import entropy
import numpy as np
from sketch import REG_FLOW, SRC, DST, PROTO, SIZE, TS

PKT_SIZE_LVL = [0, 40, 60, 80, 100, 120, 200, 400, 600, 800, 1000, 1200, 1400,
                1600, 2000]

class Stats(object):

    def __init__(self):
        self.counter = 0
        self.norm = 0

    def clear(self):
        self.counter = 0
        self.norm = 0

    def add(self):
        self.counter += 1

    def __str__(self):
        return "({}, {})".format(self.counter, self.norm)

    def __repr__(self):
        return self.__str__()

class Tprofile(object):

    def __init__(self, pkt_bins):
        self.dist =  OrderedDict()
        self.compute_pkt_level_size(pkt_bins)
        self.probs = []

    def compute_pkt_level_size(self, pkt_bins):
        for pb in pkt_bins:
            self.dist[pb] = Stats()

    def compute_dist(self):
        total = 0
        for k, v in self.dist.items():
            total += v.counter

        if total != 0:
            for k, v in self.dist.items():
                v.norm = float(v.counter)/total
                self.probs.append(v.norm)

    def clear_counter(self):
        for k, v in self.dist.items():
            v.clear()
            self.probs = []

    def add(self, pkt_size):
        keys = self.dist.keys()
        if pkt_size < keys[0]:
            raise ValueError("Invalid packet size value {}".format(pkt_size))

        i = np.digitize(pkt_size, keys)
        k = keys[i-1]
        self.dist[k].add()

    def get_max_pkt_size_level(self):
        maxval = None
        maxkey = None
        for i, v in enumerate(self.dist.values()):
            if maxval is None or maxval < v.counter:
                maxkey = i
                maxval = v.counter 
        return maxkey

    def compute_entropy(self):
        sigma = entropy(self.probs, base=2)
        # max level + 1 because it starts at 1
        imax = math.sqrt(self.get_max_pkt_size_level()+1)
        return imax * sigma

    def __str__(self):
        return str(self.dist)

    def __repr__(self):
        return self.__str__()

class TrustGuard(object):

    def __init__(self, reg, period_size, pkt_bins, quiet=True, thresh=0.5):

        self.reg = reg
        self.quiet = quiet

        self.profiles = {}
        self.pkt_bins = pkt_bins
        self.start = None
        self.end = None

        self.thresh = thresh
        self.min_threshold = None

        self.period = timedelta(seconds=period_size)
        self.current_interval = 0

        self.mal_interval = []

    def add_pkt_size(self, dip, pkt_size):
        if dip not in self.profiles:
            self.profiles[dip] = Tprofile(self.pkt_bins)

        self.profiles[dip].add(pkt_size)
    
    def clear_profile(self):
        for v in self.profiles.values():
            v.clear_counter()

    def _getdata(self, line):
        try:
            res = self.reg.match(line)
            ts = datetime.fromtimestamp(float(res.group(TS)))
            src = res.group(SRC)
            dst = res.group(DST)
            proto = res.group(PROTO)
            size = 0
            if proto != "ICMP":
                size = int(res.group(SIZE))

            return ts, src, dst, size

        except AttributeError:
            raise ValueError("Could parse line: {}".format(line))

    def run_detection(self, debug=False):
        if debug:
            pdb.set_trace()
        under_attack = False
        for k, v in self.profiles.items():
            v.compute_dist()
            entropy = v.compute_entropy()
            if entropy < self.thresh:
                under_attack = True
                if not self.quiet:
                    print("Address IP {} under attack".format(k))
                if under_attack:
                    self.mal_interval.append(self.current_interval)
            if self.min_threshold is None or entropy < self.min_threshold:
                self.min_threshold = entropy

            v.clear_counter()

    def run(self, dirname): 
        listdir = sorted(os.listdir(dirname))
        for trace in listdir:
            filename = os.path.join(dirname, trace)
            with open(filename, "r") as f:
                self.run_on_trace(f)

    def run_on_trace(self, f):
        for line in f:
            res = self._getdata(line)
            if not res:
                continue
            ts, _, dst, size = res

            if self.start is None:
                self.start = ts
                self.end = ts + self.period
            else:
                if ts >= self.end:
                    self.run_detection()
                    self.current_interval += 1
                    self.start = self.end
                    self.end = self.start + self.period
                    self.add_pkt_size(dst, size)
                else:
                    self.add_pkt_size(dst, size)

def test_trustguard():
    ipa = "10.0.0.1"
    ipb = "10.0.0.2"

    ids = TrustGuard(reg=None, period_size=5, pkt_bins=PKT_SIZE_LVL,
                     quiet=False)
    
    pkt_size_a = [300, 694, 59, 1200]
    proba = [0.2, 0.4, 0.3, 0.1]

    assert len(pkt_size_a) == len(proba)

    pkt_size_b = [193, 1300, 653, 1145, 439, 893]
    probb = [0.12, 0.08, 0.27, 0.08, 0.2, 0.25] 

    assert len(pkt_size_b) == len(probb)

    print("Normal behavior")
    for i in range(1, 1000):
        if i % 50 == 0:
            ids.run_detection()
            ids.current_interval += 1

        size_a = np.random.choice(pkt_size_a, p=proba) 
        size_b = np.random.choice(pkt_size_b, p=probb)
        ids.add_pkt_size(ipa, size_a)
        ids.add_pkt_size(ipb, size_b)

    ids.clear_profile()

    ids.thresh = ids.min_threshold

    print("Min Thresh:{}".format(ids.min_threshold))

    pkt_size_a = [20, 300, 694, 59, 1200]
    proba = [0.90, 0.02, 0.04, 0.03, 0.01]
    assert len(pkt_size_a) == len(proba)
    print("Attack behavior")
    for i in range(1, 1000):
        if i % 50 == 0:
            ids.run_detection()
            ids.current_interval += 1

        size_a = np.random.choice(pkt_size_a, p=proba)
        size_b = np.random.choice(pkt_size_b, p=probb)
        ids.add_pkt_size(ipa, size_a)
        ids.add_pkt_size(ipb, size_b)

def main(indir):

    ids = TrustGuard(reg=re.compile(REG_FLOW), period_size=5, pkt_bins=PKT_SIZE_LVL)
    ids.run(indir)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--indir", type=str, dest="indir")

    args = parser.parse_args()
    indir = args.indir
    #main(indir)
    test_trustguard()
