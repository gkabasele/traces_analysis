import re
import os
import random
import argparse
import math
import logging
from datetime import datetime
from datetime import timedelta
from collections import OrderedDict
import numpy as np
from scipy import stats
from welford import Welford


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

logname = "flow_res.log"
if os.path.exists(logname):
    os.remove(logname)
logging.basicConfig(format='%(levelname)s:%(message)s', filename=logname, level=level)

key_attr = ["src", "sport", "dst", "dport"]
class RecordKey(object):

    def __init__(self, src, sport, dst, dport):
        self.src = src
        self.sport = sport
        self.dst = dst
        self.dport = dport

    def __eq__(self, other):
        return (self.src == other.src and self.dst == other.dst and
                self.sport == other.sport and self.dport == other.dport)

    def __hash__(self):
        return hash((self.src, self.dst, self.sport, self.dport))

    def __str__(self):
        return "{}:{}->{}:{}".format(self.src, self.sport, self.dst, self.dport)

    def __repr__(self):
        return self.__str__()

class FlowRecord(object):

    def __init__(self, key, tlast=None):
        self.key = key
        self.tlast = tlast
        self.pkts = 0
        self.pkt_byte = Welford()
        self.size = 0
        self.pkt_ipt = Welford()
        self.score = 0
        self.number_seen = 0

    def __getattr__(self, attr):
        if attr in key_attr:
            return getattr(self.key, attr)
        elif attr in self.__dict__:
            return self.__dict__[attr]
        else:
            raise AttributeError("Object has no attribute %s" % attr)

    def __repr__(self):
        return self.key.__repr__()

    def __str__(self):
        return self.key.__str__()

    @property
    def avg_byte(self):
        return self.pkt_byte.mean

    @property
    def var_byte(self):
        return self.pkt_byte.std**2

    @property
    def avg_ipt(self):
        return self.pkt_ipt.mean

    @property
    def var_ipt(self):
        return self.pkt_ipt.std**2

    def reset(self):
        self.pkts = 0
        self.pkt_byte = Welford()
        self.size = 0
        self.pkt_ipt = Welford()
        self.score = 0

    def update_record(self, ts, size):
        cur = ts
        if self.tlast:
            ipt = (cur - self.tlast).total_seconds()
        else:
            ipt = 0
        self.tlast = cur
        self.pkt_byte(size)
        self.pkt_ipt(ipt)
        self.size += size
        self.pkts += 1

    def compute_tstat(self, avg, havg, var, pkts):
        if var > 0 and pkts > 0:
            return (avg - havg) / (math.sqrt(var/pkts))

    # Differnce between two groups and the difference within the groups
    # A large score indicates a difference the group, a small score suggest the
    # reverse
    def update_score(self, hist_record, alpha=0.05):
        df = self.pkts - 1

        crit_byte = stats.t.ppf(1-alpha, df=df) 
        t_byte = self.compute_tstat(self.avg_byte, hist_record.avg_byte,
                                    self.var_byte, self.pkts)
        if t_byte and t_byte > crit_byte:
            logging.info("Bytes rej. H0, crit:%s t:%s for %s", crit_byte, t_byte, self)

        crit_ipt = stats.t.ppf(1-alpha, df=df)
        t_ipt = self.compute_tstat(self.avg_ipt, hist_record.avg_ipt, self.var_ipt,
                                   self.pkts)

        if t_ipt and t_ipt > crit_ipt:
            logging.info("IPT rej. H0, crit:%s t:%s for %s", crit_ipt, t_ipt, self)
        if t_byte and t_ipt:
            self.score = math.sqrt(t_byte**2 + t_ipt**2)

class HistoricalRecord(object):

    def __init__(self, key, update_time=None):
        self.key = key 
        self.update_time = update_time
        self.pkts = 0
        self.avg_byte = 0
        self.var_byte = 0
        self.avg_ipt = 0
        self.var_ipt = 0

    def __getattr__(self, attr):
        if attr in key_attr:
            return getattr(self.key, attr)
        elif attr in self.__dict__:
            return self.__dict__[attr]
        else:
            raise AttributeError("Object has no attribute %s" % attr)

    def combine_stats(self, m, xa, n, xb):
        return (m * xa + n * xb)/float(m + n)

    def update_record(self, record, ts):
        self.avg_byte = self.combine_stats(self.pkts, self.avg_byte,
                                           record.pkts, record.avg_byte)
        self.var_byte = self.combine_stats(self.pkts, self.var_byte,
                                           record.pkts, record.var_byte)
        self.avg_ipt = self.combine_stats(self.pkts, self.avg_ipt, record.pkts,
                                          record.avg_ipt)
        self.var_ipt = self.combine_stats(self.pkts, self.var_ipt, record.pkts,
                                          record.var_ipt)
        self.pkts += record.pkts
        self.update_time = ts


class FlowIDS(object):

    def __init__(self, dirname, match, tresh=0.5, period=180, aging=1.0,
                 number_seen=40, alpha=0.001):
        self.f_records = OrderedDict()
        self.h_records = OrderedDict()
        self.dirname = dirname
        self.reg = match
        self.tresh = tresh
        self.period = timedelta(seconds=period)
        self.alpha = alpha
        self.start = None
        self.stop = None
        self.aging = aging
        #Quant, nubmer of packet before computing score
        self.number_seen = number_seen

    def _getdata(self, line):
        res = self.reg.match(line)
        ts = datetime.fromtimestamp(float(res.group(TS)))
        src = res.group(SRC)
        dst = res.group(DST)
        sport = res.group(SPORT)
        dport = res.group(DPORT)
        size = int(res.group(SIZE))
        return ts, src, sport, dst, dport, size

    def reset_flow_record(self):
        for _, v in self.f_records.items():
            v.reset()

    def update_historical(self, ts):
        for k, v in self.f_records.items():

            if v.key in self.h_records:
                record = self.h_records[v.key]
            else:
                logging.info("New flow %s", v)
                record = HistoricalRecord(v.key)
                self.h_records[v.key] = record
            if v.number_seen >= self.number_seen:
                v.update_score(record, alpha=self.alpha)
            record.update_record(v, ts)
            v.number_seen += 1

    def run_detection(self):
        period_id = 0
        for trace in os.listdir(self.dirname):
            filename = os.path.join(self.dirname, trace)
            with open(filename, "r") as f:
                for line in f:
                    ts, src, sport, dst, dport, size = self._getdata(line)
                    if not self.start:
                        self.start = ts
                        self.stop = ts + self.period
                        logging.info("Start time: %s", self.start)
                        logging.info("Stop time: %s", self.stop)

                    if ts > self.stop:
                        logging.info("Period %s done updating", period_id)
                        self.update_historical(ts)
                        self.start = self.stop
                        self.stop = ts + self.period
                        self.reset_flow_record()
                        logging.info("Start time: %s", self.start)
                        logging.info("Stop time: %s", self.stop)
                        period_id += 1
                        logging.info("Period %s", period_id)

                    else:
                        key = RecordKey(src, sport, dst, dport)
                        if key in self.f_records: 
                            record = self.f_records[key]
                        else:
                            record = FlowRecord(key)
                            self.f_records[key] = record
                        record.update_record(ts, size)

def simple_update(flow, size, ipt):
    flow.pkt_byte(size)
    flow.pkt_ipt(ipt)
    flow.size += size 
    flow.pkts += 1

def test():
    handler = FlowIDS("", re.compile(REG))
    mu, sigma = 500, 10
    byte = np.random.normal(mu, sigma, 100)

    mu, sigma = 10, 4
    ipt = np.random.normal(mu, sigma, 100)

    key= RecordKey("a", 120, "b", 200)
    fr1 = FlowRecord(key)

    for s, i in zip(byte, ipt):
        simple_update(fr1, s, i)

    print("{}, AvgB: {}, VarB:{}, AvgIPT:{}, VarIPT:{}".format(fr1, fr1.avg_byte,
                                                               fr1.var_byte,
                                                               fr1.avg_ipt,
                                                               fr1.var_ipt))
    handler.f_records[key] = fr1
    handler.update_historical("")
    handler.reset_flow_record()

    mu, sigma = 500, 10
    byte = np.random.normal(mu, sigma, 100)

    mu, sigma = 10, 4
    ipt = np.random.normal(mu, sigma, 100)

    for s, i in zip(byte, ipt):
        simple_update(fr1, s, i)

    print("{}, AvgB: {}, VarB:{}, AvgIPT:{}, VarIPT:{}".format(fr1, fr1.avg_byte,
                                                               fr1.var_byte,
                                                               fr1.avg_ipt,
                                                               fr1.var_ipt))
    handler.update_historical("")
    hr = handler.h_records[key]
    fr1.update_score(hr)
    print("Score: {}".format(fr1.score))
    handler.reset_flow_record()

    #DOS
    mu, sigma = 1000, 5
    byte = np.random.normal(mu, sigma, 1000)

    mu, sigma = 5, 2
    ipt = np.random.normal(mu, sigma, 1000)

    for s, i in zip(byte, ipt):
        simple_update(fr1, s, i)

    print("{}, AvgB: {}, VarB:{}, AvgIPT:{}, VarIPT:{}".format(fr1, fr1.avg_byte,
                                                               fr1.var_byte,
                                                               fr1.avg_ipt,
                                                               fr1.var_ipt))
    hr = handler.h_records[key]
    fr1.update_score(hr)
    print("Score: {}".format(fr1.score))


def main(dirname):
    handler = FlowIDS(dirname, re.compile(REG), period=30, number_seen=10)
    handler.run_detection()

if __name__=="__main__":
    main(indir)
    #test()
