import re
import sys
import random
import os
import argparse
import logging
import pdb
from datetime import datetime
from datetime import timedelta
from collections import OrderedDict
import numpy as np

REG =r"(?P<ts>(\d+\.\d+)) IP (?P<src>(?:\d{1,3}\.){3}\d{1,3})(\.(?P<sport>\d+)){0,1} > (?P<dst>(?:\d{1,3}\.){3}\d{1,3})(\.(?P<dport>\d+)){0,1}: (?P<proto>(tcp|TCP|udp|UDP|icmp|ICMP))( |, length )(?P<size>\d+){0,1}"
 

TS = "ts"
SRC = "src"
SPORT = "sport"
DST = "dst"
DPORT = "dport"
PROTO = "proto"
SIZE = "size"



class Pattern(object):

    def __init__(self):
        # to_ip_address -> #pktssend
        self.vector = {}
        self.hist_count = 0
        self.hist_prob = 0
        self.hist_tail = 0

    def __repr__(self):
        return self.__str__()

    def __str__(self):
        return "Vr: {}, Ct: {}, Pb: {}".format(self.vector, self.hist_count,
                                               self.hist_prob)

    def add_destination(self, dst):
        if dst in self.vector:
            self.vector[dst] += 1
        else:
            self.vector[dst] = 1

    def _getkeys(self, othervector):
        return reduce(set.union, map(set, map(dict.keys, [self.vector,
                                                          othervector])))

    #Add key that are missing in one of the vector
    def fill_keys(self, allkeys, keys):
        for k in allkeys:
            if k not in keys:
                keys.append(k)

    def fill_values(self, keys, vector):
        val = []
        for k in keys:
            if k in vector:
                val.append(vector[k])
            else:
                val.append(0)
        return val

    def uniformize(self, other):
        allkeys = self._getkeys(other.vector)
        keys = self.vector.keys()
        other_keys = other.vector.keys()

        self.fill_keys(allkeys, keys)
        self.fill_keys(allkeys, other_keys)

        s_keys = sorted(keys)
        so_keys = sorted(other_keys)

        s_vals = np.array(self.fill_values(s_keys, self.vector))
        so_vals = np.array(self.fill_values(so_keys, other.vector))

        s_tup = (s_keys, s_vals)
        so_tup = (so_keys, so_vals)

        return s_tup, so_tup

    def adapt(self, pattern):
        s_tup, so_tup = self.uniformize(pattern)
        pat_k = s_tup[1]
        cur = so_tup[1]
        adapted_val = (1./(self.hist_count + 1)) * (self.hist_count * pat_k + cur)
        self.vector = dict(zip(s_tup[0], adapted_val))


    def similarity(self, other):
        s_tup, so_tup = self.uniformize(other)
        dot = np.dot(s_tup[1], so_tup[1])
        norma = np.linalg.norm(s_tup[1])
        normb = np.linalg.norm(so_tup[1])
        dist = dot/(norma * normb)
        return dist

    def normalize(self):
        total = sum([x for x in self.vector.values()])
        for k, v in self.vector.items():
            self.vector[k] = v/float(total)


class PatternIDS(object):

    def __init__(self, dirname, match, tresh_match=0.7, tresh_alert=0.5,
                 period=30):

        self.dirname = dirname
        self.tresh_match = tresh_match
        self.tresh_alert = tresh_alert
        self.reg = match
        self.period = timedelta(seconds=period)
        #Map IP -> Pattern}
        self.patterns_lib = OrderedDict() 
        self.patterns = OrderedDict()
        self.start = None
        self.stop = None
        self.number_alert = []
        self.current_interval = 0
        self.mal_interval = set()
        self.alert = 0

    def find_closest_pattern(self, ip, pattern):
        sim = -1
        minpat_index = -1
        for i, pat in enumerate(self.patterns_lib[ip]):
            tmp_sim = pat.similarity(pattern)
            if sim < 0 or tmp_sim >= sim:
                sim = tmp_sim
                minpat_index = i
        return minpat_index, sim

    def update_pattern(self):
        winning_pat = []
        for k, v in self.patterns.items():
            v.normalize()
            index, sim = self.find_closest_pattern(k, v)
            if index >= 0 and sim >= self.tresh_match:
                logging.debug("A match has been found for host %s: %s, %s",
                              k, index, sim)
                pattern = self.patterns_lib[k][index]
                logging.debug("%s", pattern)
                pattern.adapt(v)
                pattern.hist_count += 1
                winning_pat.append((k, pattern))
            else:
                logging.debug("No match has been found for host %s: %s, %s",
                              k, index, sim)
                if len(v.vector) > 2:
                    #pdb.set_trace()
                    pass
                logging.debug("New pattern : %s", v)
                v.hist_count += 1
                self.patterns_lib[k].append(v)
        return winning_pat

    def update_prob(self, winning_pat):
        for k, v in winning_pat:

            total = sum([x.hist_count for x in self.patterns_lib[k]])

            v.hist_prob = v.hist_count/float(total)
            v.hist_tail = sum([x.hist_prob for x in self.patterns_lib[k]
                                     if x.hist_prob <= v.hist_prob])
            if v.hist_tail <= self.tresh_alert:
                logging.info("Alert %s for pattern %s", k, v)
                self.alert += 1
                self.mal_interval.add(self.current_interval)

    def _getdata(self, line):
        res = self.reg.match(line)
        ts = datetime.fromtimestamp(float(res.group(TS)))
        srcip = res.group(SRC)
        dstip = res.group(DST)
        return ts, srcip, dstip

    def display_pattern(self):

        for k, v in self.patterns_lib.items():
            s = "IP: {} ".format(k)
            for pat in v:
                s +=  str(pat) + " "
            print(s)

    def run(self):
        period_id = 0
        listdir = sorted(os.listdir(self.dirname))
        for trace in listdir: 
            filename = os.path.join(self.dirname, trace)
            print filename
            with open(filename, "r") as f:
                for line in f:
                    ts, srcip, dstip = self._getdata(line)
                    if not self.start:
                        self.start = ts
                        self.stop = self.start + self.period
                        logging.info("Start time: %s", self.start)
                        logging.info("Stop time: %s", self.stop)

                    if ts > self.stop:
                        logging.info("Period %s done updating", period_id)
                        logging.info("IPs: %s", self.patterns.keys())
                        winning_pat = self.update_pattern()
                        self.update_prob(winning_pat)
                        self.number_alert.append(self.alert)  
                        self.alert = 0
                        self.current_interval += 1
                        period_id += 1

                        #self.display_pattern()

                        self.start = self.stop
                        self.stop = self.start + self.period
                        logging.info("Start time: %s", self.start)
                        logging.info("Stop time: %s", self.stop)
                        logging.info("Period: %s", period_id)

                        self.patterns = {}

                    pat = Pattern() if srcip not in self.patterns else self.patterns[srcip]
                    
                    pat.add_destination(dstip)
                    self.patterns[srcip] = pat

                    pat = Pattern() if dstip not in self.patterns else self.patterns[dstip]

                    pat.add_destination(srcip)
                    self.patterns[dstip] = pat
                    

                    if srcip not in self.patterns_lib:
                        self.patterns_lib[srcip] = []

                    if dstip not in self.patterns_lib:
                        self.patterns_lib[dstip] = []
        logging.info("%s", self.number_alert)
def test_similarity():
    pat1 = Pattern()
    # sum Ai . Bi / sqrt(sum A**2) * sqrt(sum B**2)
    # 11438,41 / 12113,927
    #
    pat1.vector = {"a": 13.33, "c": 19.33, "j": 4.0, "d": 13.0, "f": 5.33}
    pat2 = Pattern()
    pat2.vector = {"a": 297, "c": 280, "d": 159}

    print(pat1.similarity(pat2))

def test_update_prob():

    handler = PatternIDS("", re.compile(REG), period=4)
    src = "src"
    pat1 = Pattern()
    pat2 = Pattern()
    diff_pat = Pattern()
    vol_pat = Pattern()

    dest1 = ["a", "c", "d"]
    dest2 = ["a", "c", "d"]

    handler.patterns_lib[src] = []

    #First round
    for k in dest1:
        for _ in xrange(random.randint(5, 30)):
            pat1.add_destination(k)

    print(pat1)
    handler.patterns[src] = pat1
    winning_pat = handler.update_pattern()
    handler.update_prob(winning_pat)
    print(pat1)

    #Second round
    for k in dest2:
        for _ in xrange(random.randint(5, 30)):
            pat2.add_destination(k)

    print(pat2)
    handler.patterns[src] = pat2
    winning_pat = handler.update_pattern()
    handler.update_prob(winning_pat)
    print(pat1)

    #Third round
    for k in dest1:
        for _ in xrange(random.randint(5,30)):
            diff_pat.add_destination(k)
    for _ in xrange(random.randint(500, 1000)):
            diff_pat.add_destination("f")

    print(diff_pat)
    handler.patterns[src] = diff_pat
    winning_pat = handler.update_pattern()
    handler.update_prob(winning_pat)
    print(pat1)

def main(dirname):
    ids = PatternIDS(dirname, re.compile(REG), period=30)
    ids.run()

if __name__ == "__main__":

    parser = argparse.ArgumentParser()
    parser.add_argument("--indir", type=str, dest="indir")
    parser.add_argument("--level", type=str, dest="level")
    
    
    args = parser.parse_args()
    indir = args.indir
    try:
        level = args.level
        if level == "debug" or level is None:
            level = logging.DEBUG
        elif level == "info":
            level = logging.INFO
        elif level == "warning" or level == "warn":
            level = logging.WARNING
    except AttributeError:
        pass
    
    logname = "pattern_res_debug_short_scan.log"
    if os.path.exists(logname):
        os.remove(logname)
    logging.basicConfig(format='%(levelname)s:%(message)s', filename=logname, level=level)


    main(indir)
    #test_update_prob()
