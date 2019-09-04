import re
import sys
import os
import argparse
import logging
import random
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

    def __init__(self, alpha, cthresh, big_M, csum, nbr_interval,
                 thresh_sum_upper):
        self.alpha = alpha
        self.cthresh = cthresh
        self.csum = csum
        self.big_M = big_M
        self.thresh_sum = 0
        self.nbr_interval = nbr_interval
        self.errors_std = 0.0
        self.thresh_sum_upper = thresh_sum_upper
        self.errors = []

        self.last_val = None
        self.forecasted = None   # forecasted for t+1
        self.upper = None
        self.uppersum = None
        self.last_norm_obs = []

        self.under_attack = False

        self.mal_interval = []

    def estimate_next(self, obs, debug=False):
        if debug:
            pdb.set_trace()
        if not self.under_attack:
            self.forecasted = self.alpha * obs + (1-self.alpha)*self.last_val
            self.last_norm_obs.append(obs)
            if len(self.last_norm_obs) > 10:
                self.last_norm_obs.pop(0) 
        else:
            last = self.last_norm_obs[random.randint(0, len(self.last_norm_obs)-1)]
            self.forecasted = self.alpha * last + (1-self.alpha)*self.last_val

    def compute_error(self, obs, debug=False):
        if debug:
            pdb.set_trace()

        if len(self.errors) < 2:
            self.errors_std = 0
        else:
            self.errors_std = np.std(self.errors)

        self.upper = self.forecasted + max(self.cthresh*self.errors_std,
                                               self.big_M)

        self.errors.append(obs - self.forecasted)

    def compute_cumsum(self, obs, debug=False):
        if debug:
            pdb.set_trace()
        self.thresh_sum = min(self.thresh_sum_upper, 
                              max(self.thresh_sum + (obs - self.upper), 0))
        self.uppersum = self.csum * self.errors_std

    def update_forecast(self, is_anomaly):
        self.under_attack = is_anomaly
        if self.under_attack:
            self.errors.pop(len(self.errors)-1)
        else:
            if len(self.errors) > self.nbr_interval:
                self.errors.pop(0)
            self.last_val = self.forecasted

    def raise_alert(self, obs, interval):
        print("Alert fore:{}, obs:{} in interval {}".format(self.forecasted,
                                                            obs, interval))

    def run(self, timeseries):
        for i in range(len(timeseries)-1):
            x_t = timeseries[i]
            x_next = timeseries[i+1]
            self.estimate_next(x_t)
            self.compute_error(x_next)
            self.compute_cumsum(x_next)
            if self.thresh_sum > self.uppersum:
              self.raise_alert(x_next, i)
              self.mal_interval.append(i)
            self.update_forecast(self.thresh_sum > self.uppersum)

def main(dirname):
    #interval_size = 30
    interval_size = 5
    exporter = FlowCreationCounter(interval_size, re.compile(REG), dirname)
    ts_creation_flow = exporter.new_flow_ts()
    span = 900
    N = math.ceil(span/interval_size) 
    alpha = float(2)/(N+1)
    cthresh = 1.5
    csum = 4
    big_M = 0
    thresh_sum_upper = 50 
    analyzer = TSAnalyzer(alpha, cthresh, big_M, csum, N, thresh_sum_upper)
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
            print("Alert fore:{}, obs:{} in interval {}".format(forecasted_values[i+1],
                                                                x_next, i))
        analyzer.update_forecast(analyzer.thresh_sum > analyzer.uppersum)

    print("LR: {}, LF: {}".format(len(ts_creation_flow),
                                  len(forecasted_values)))
    plot(ts_creation_flow, forecasted_values, label1='real',
         label2='forecasted', style1="-", style2="-")

    plot(thresh_sum, uppersum, label1='val', label2='thresh', style1="-",
         style2="--")

def plot(data, forecasted_data=None, **kwargs):
    xs = np.arange(len(data))
    plt.plot(xs, data, kwargs['style1'],label=kwargs['label1'])
    if forecasted_data is not None:
        plt.plot(xs, forecasted_data, kwargs['style2'], label=kwargs['label2'])
    plt.legend(loc='upper right')
    plt.show()


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
    thresh_sum_upper = 10

    analyzer = TSAnalyzer(alpha, cthresh, big_M, csum, nbr_interval,
                          thresh_sum_upper)
    analyzer.last_val = 0
    computed = []
    for i, x in enumerate(ts):
        try:
            analyzer.estimate_next(x)
            res = Decimal(analyzer.forecasted).quantize(Decimal('.001'),
                                                           rounding=ROUND_UP)
            expect = Decimal(str(estimated[i]))
            assert res == expect
        except AssertionError:
            print("AssertionError: expected: {}, got: {}".format(expect, res))

def test_ewma_ids():

    n_inter = 200
    interval_size = 5
    min_val = 5
    max_val = 25
    span = 20
    ts = [random.randint(min_val, max_val) for _ in range(n_inter)]

    n_inter_atk = 30
    atk_min = 150
    atk_max = 300
    tmp = [random.randint(atk_min, atk_max) for _ in range(n_inter_atk)]
    ts.extend(tmp)
    ts.extend(ts[:200])

    N = math.ceil(span/interval_size)
    alpha = float(2)/(N+1)
    cthresh = 3
    csum = 1.5
    big_M = 20
    thresh_sum_upper = 50
    ids = TSAnalyzer(alpha, cthresh, big_M, csum, N, thresh_sum_upper)
    ids.last_val = ts[0]
    forecasted_values = [ts[0]]
    thresh_sum = []
    uppersum = []

    debug = False

    for i in range(len(ts)-1):
        x_t = ts[i]
        x_next = ts[i+1]
        ids.estimate_next(x_t)
        forecasted_values.append(ids.forecasted)
        ids.compute_error(x_next, debug)
        ids.compute_cumsum(x_next, debug)
        thresh_sum.append(ids.thresh_sum)
        uppersum.append(ids.uppersum)
        if ids.thresh_sum > ids.uppersum:
            print("Alert fore:{}, obs:{} in interval {}".format(forecasted_values[i+1], x_next, i))

        ids.update_forecast(ids.thresh_sum > ids.uppersum)

    plot(ts, forecasted_values, label1='real',
         label2='forecasted', style1="-", style2="-")

    plot(thresh_sum, uppersum, label1='val', label2='thresh', style1="-",
         style2="--")

if __name__== "__main__":
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

    #test_ewma()
    #test_ewma_ids()
    main(indir)
