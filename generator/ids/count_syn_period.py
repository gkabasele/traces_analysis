import os
import re
import pdb
import argparse
from datetime import datetime, timedelta
import numpy as np
import matplotlib.pyplot as plt

REG =r"(?P<ts>(\d+\.\d+)) IP (?P<src>(?:\d{1,3}\.){3}\d{1,3})(\.(?P<sport>\d+)){0,1} > (?P<dst>(?:\d{1,3}\.){3}\d{1,3})(\.(?P<dport>\d+)){0,1}: Flags (?P<flag>(?:\[\w*\.{0,1}]))"

TS = "ts"
SRC = "src"
SPORT = "sport"
DST = "dst"
DPORT = "dport"
PROTO = "proto"
SIZE = "size"
FLAG = "flag"

class Params(object):

    def __init__(self):
        self.start = None
        self.end = None
        self.nbr_syn = 0
        self.interval = 0
        self.syn_per_ip = {}
        self.ts_per_ip =  {}
        self.syn_timeseries = []

    def add(self, ip):
        if ip not in self.syn_per_ip:
            self.syn_per_ip[ip] = 0

        self.syn_per_ip[ip] += 1

    def clear(self):
        for ip in self.syn_per_ip:
            if ip not in self.ts_per_ip:
                self.ts_per_ip[ip] = []
                for _ in range(self.interval):
                    self.ts_per_ip[ip].append(0)
            self.ts_per_ip[ip].append(self.syn_per_ip[ip])
            self.syn_per_ip[ip] = 0

def convert(dt):
    epoch = datetime.utcfromtimestamp(0)
    return (dt - epoch).total_seconds()
    
def getdata(line, reg):
    res = reg.match(line)
    ts = datetime.fromtimestamp(float(res.group(TS)))
    src = res.group(SRC)
    dst = res.group(DST)
    sport = res.group(SPORT)
    dport = res.group(DPORT)
    flag = res.group(FLAG)
    return ts, src, sport, dst, dport, flag

def run(dirname, params, period_size, reg):
    listdir = sorted(os.listdir(dirname))
    for trace in listdir:
        filename = os.path.join(dirname, trace)
        with open(filename, "r") as f:
            count_syn(f, params, period_size, reg)

# Count packet received by destination
def count_syn(f, params, period_size, reg):
    for line in f:
        res = getdata(line, reg)
        if not res:
            continue
        ts, src, sport, dst, dport, flag = res
        if params.start is None:
            params.start = ts
            params.end = ts + period_size
            params.add(dst)
        else:
            if ts >= params.end:
                params.clear()
                params.interval += 1
                params.start = params.end
                params.end = params.end + period_size
                params.add(dst)
            else:
                params.add(dst)

def plot(data):
    x_axis = np.arange(len(data))
    plt.plot(x_axis, data)

def main(indir):
    period_size = timedelta(seconds=15)
    reg = re.compile(REG)
    params = Params()
    run(indir, params, period_size, reg)
    for k, v in params.ts_per_ip.items():
        print("IP:{}  {}".format(k, v))
        plot(v)
    plt.show()
if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--indir", type=str, dest="indir")
    args = parser.parse_args()
    indir = args.indir
    main(indir)
