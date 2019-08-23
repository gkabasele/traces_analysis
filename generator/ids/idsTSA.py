import re
import sys
import os
import argparse
import logging
import pdb
import math
from datetime import datetime
from datetime import timedelta
from collections import OrderedDict
import numpy as np
import matplotlib.pyplot as plt 
from decimal import *

REG =r"(?P<ts>(\d+\.\d+)) IP (?P<src>(?:\d{1,3}\.){3}\d{1,3})(\.(?P<sport>\d+)){0,1} > (?P<dst>(?:\d{1,3}\.){3}\d{1,3})(\.(?P<dport>\d+)){0,1}: (?P<proto>(tcp|TCP|udp|UDP|icmp|ICMP))( |, length )(?P<size>\d+){0,1}"

TS = "ts"
SRC = "src"
SPORT = "sport"
DST = "dst"
DPORT = "dport"
PROTO = "proto"
SIZE = "size"


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

logname = "tsa_res_debug.log"
if os.path.exists(logname):
    os.remove(logname)
logging.basicConfig(format='%(levelname)s:%(message)s', filename=logname, level=level)

class FlowRecord(object):

    __slots__ = ['src', 'dst', 'sport','dport', 'proto', 'ts']

    def __init__(self, src, dst, sport, dport, proto, ts):
        self.src = src
        self.dst = dst
        self.sport = sport
        self.dport = dport
        self.proto = proto
        self.ts = ts

    def __hash__(self):
        return hash((self.src, self.sport, self.dst, self.dport, self.proto))

    def __eq__(self, other):
        return hash(other) == self.__hash__()

    def __str__(self):
        return "{}:{}->{}:{} ({})".format(self.src, self.sport,
                                          self.dst, self.dport,
                                          self.proto)
    def __repr__(self):
        return self.__str__()

class FlowCreationCounter(object):

    def __init__(self, period_size, match, dirname):
        #in seconds
        self.period_size = timedelta(seconds=period_size)
        self.reg = match
        self.dirname = dirname

    def _getdata(self, line):
        try:
            res = self.reg.match(line)
            ts = datetime.fromtimestamp(float(res.group(TS)))
            src = res.group(SRC)
            dst = res.group(DST)
            sport = res.group(SPORT)
            dport = res.group(DPORT)
            proto = res.group(PROTO)
            size = 0
            if proto != "ICMP":
                size = int(res.group(SIZE))
        except TypeError:
            return
        return FlowRecord(src, dst, sport, dport, proto, ts)

    def clear_array(self, flow_array, index):
        keys = flow_array.keys()
        for k, v in flow_array.items():
            if v != index:
                flow_array.pop(k, None)

    def new_flow_ts(self):
        start_time = None
        end_time = None
        listdir = sorted(os.listdir(self.dirname))
        new_flow = []
        counter = 0
        index_period = 0
        flow_array = OrderedDict()
        # if there is a gap larger than a period between two consecutive seen flows 
        # (Does not occur generally as it means no packet for 1 periods)
        tmp_flow = None
        for trace in listdir:
            filename = os.path.join(self.dirname, trace)
            with open(filename, "r") as f:
                for line in f:
                    flow = self._getdata(line)
                    if flow is None:
                        continue
                    if start_time is None and end_time is None:
                        start_time = flow.ts
                        end_time = flow.ts + self.period_size

                    if flow.ts > end_time:
                        new_flow.append(counter)
                        self.clear_array(flow_array, index_period)
                        start_time = end_time
                        end_time = start_time + self.period_size
                        counter = 0
                        index_period += 1

                    if flow.ts < end_time:
                        if flow not in flow_array:
                            flow_array[flow] = index_period
                            counter += 1
                        else:
                            flow_array[flow] = index_period

        return np.array(new_flow)

class TSAnalyzer(object):
    
    # Implementation of paper: Towards Real-Time Intrusion Detection for Netflow
    # and IPFIX

    def __init__(self, alpha, cthresh, big_M, csum, nbr_interval):
        self.alpha = alpha
        self.cthresh = cthresh
        self.csum = csum
        self.big_M = big_M
        self.last_val = None
        self.observed_val = None # observed in t
        self.weighted_val = None # weighted for t
        self.forecasted = None   # forecasted for t+1
        self.upper = None
        self.thresh_sum = 0
        self.uppersum = None
        self.errors = []
        self.errors_std = None
        self.nbr_interval = nbr_interval

    def estimate_next(self, obs):
        self.estimated_val = self.alpha * obs + (1-self.alpha)*self.last_val
        self.forecasted = self.estimated_val
        self.last_val = self.estimated_val

    def compute_error(self, obs):
        if len(self.errors) >= self.nbr_interval:
            self.errors.pop(0)

        self.errors.append(obs - self.forecasted)
        self.errors_std = np.std(self.errors)
        self.upper = self.forecasted + max(self.cthresh*self.errors_std,
                                              self.big_M)

    def compute_cumsum(self, obs):
        self.thresh_sum = max(self.thresh_sum + (obs - self.upper), 0)
        self.uppersum = self.csum * self.errors_std

def main(dirname):
    interval_size = 5
    exporter = FlowCreationCounter(interval_size, re.compile(REG), dirname)
    ts_creation_flow = exporter.new_flow_ts()
    span = 15
    N = math.ceil(span/interval_size) 
    alpha = float(2/(N+1))
    cthresh = 1
    csum = 7
    big_M = 0
    analyzer = TSAnalyzer(alpha, cthresh, big_M, csum, N)
    analyzer.last_val = ts_creation_flow[0]
    forecasted_values = [analyzer.last_val]
    thresh_sum = []
    uppersum = []
    for i in range(len(ts_creation_flow)-1):
        x_t = ts_creation_flow[i]
        x_next = ts_creation_flow[i+1]
        analyzer.estimate_next(x_t)
        forecasted_values.append(analyzer.forecasted)
        analyzer.compute_error(x_next)
        analyzer.compute_cumsum(x_next)
        thresh_sum.append(analyzer.thresh_sum)
        uppersum.append(analyzer.uppersum)
        if analyzer.thresh_sum > analyzer.uppersum:
            print("Warn:forecasted:{},observed:{}".format(forecasted_values[i+1],
                                                          x_next))
    print("LR: {}, LF: {}".format(len(ts_creation_flow),
                                  len(forecasted_values)))
    plot(ts_creation_flow, forecasted_values)

    plot(thresh_sum, uppersum)
def test_ewma():

    ts = [1, -0.5, 0.0, -0.8, -0.8, -1.2, 1.5, -0.6, 1, -0.9, 1.2, 0.5, 2.6,
          0.7, 1.1, 2.0]

    estimated = [0.250, 0.063, 0.047, -0.165, -0.324, -0.543, -0.033, -0.175,
                 0.120, -0.136, 0.199, 0.274, 0.856, 0.817, 0.888, 1.166]
    alpha = 0.25
    cthresh = 1.5
    big_M = 5000
    csum = 5
    nbr_interval = 5

    analyzer = TSAnalyzer(alpha, cthresh, big_M, csum, nbr_interval)
    analyzer.last_val = 0
    computed = []
    for i, x in enumerate(ts):
        try:
            analyzer.estimate_next(x)
            res = Decimal(analyzer.estimated_val).quantize(Decimal('.001'),
                                                           rounding=ROUND_UP)
            expect = Decimal(str(estimated[i]))
            assert res == expect
        except AssertionError:
            print("AssertionError: expected: {}, got: {}".format(expect, res))

    # from https://school.stockcharts.com/doku.php?id=technical_indicators:moving_averages

    ts = [22.27, 22.19, 22.08, 22.17, 22.18, 22.13, 22.23, 22.43, 22.24, 22.29,
          22.15, 22.39, 22.38, 22.61, 23.36, 24.05, 23.75, 23.83, 23.95, 23.63,
          23.82, 23.87, 23.65, 23.19, 23.10, 23.33, 22.68, 23.10, 22.50, 22.17]

    estimated = [22.22, 22.21, 22.24, 22.27, 22.33, 22.52, 22.80, 22.97, 23.13,
                 23.28, 23.34, 23.43, 23.51, 23.54, 23.47, 23.40, 23.39, 23.26,
                 23.23, 23.08, 22.92]

    alpha = 0.1818
    analyzer = TSAnalyzer(alpha, cthresh, big_M, csum, nbr_interval)
    analyzer.last_val = np.mean(ts[0:10])
    forecasted = [analyzer.last_val]
    for i in range(10, len(ts)-1):
        analyzer.estimate_next(ts[i])
        forecasted.append(analyzer.forecasted)
    plot(ts[10:], forecasted)
def plot(data, forecasted_data=None):
    xs = np.arange(len(data))
    plt.plot(xs, data)
    if forecasted_data is not None:
        plt.plot(xs, forecasted_data)
    plt.show()

if __name__== "__main__":
    test_ewma()
    #main(indir)
