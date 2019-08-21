import re
import sys
import os
import argparse
import logging
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
        return hash((self.src, self.dst, self.dport))

    def __str__(self):
        return "{}:{}->{}:{} ({})".format(self.src, self.sport,
                                          self.dst, self.dport,
                                          self.proto)

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
        flow_array = {}
        for trace in listdir:
            filename = os.path.join(self.dirname, trace)
            with open(filename, "r") as f:
                for line in f:
                    flow = self._getdata(line)
                    if flow is None:
                        continue
                    if start_time is None and end_time is None:
                        start_time = f.ts
                        end_time = f.ts + self.period_size

                    if f.ts < end_time:
                        if f not in flow_array:
                            flow_array[f] = index_period
                            counter += 1
                    else:
                        new_flow.append(counter)
                        self.clear_array(flow_array, index_period)
                        start_time = end_time
                        end_time = start_time + self.period_size
                        counter = 0
                        index_period += 1
                        if f.ts < end_time:
                            if f not in flow_array:
                                flow_array[f] = index_period
                                counter += 1
        return np.array(new_flow)
