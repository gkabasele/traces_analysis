import re
import os
import argparse
from datetime import datetime
from datetime import timedelta
import matplotlib.pyplot as plt
import matplotlib as mpl
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
parser.add_argument("-r", "--realdir", type=str, action="store", dest="real")
parser.add_argument("-g","--gendir", action='append', type=str, dest="gen")
parser.add_argument("-p", "--period", action=int, type=str, dest="period")

args = parser.parse_args()

gendirs = args.gen
realdir = args.real
period = args.period

regex = re.compile(REG)

def getdata(line):
    try:
        res = regex.match(line)
        ts = datetime.fromtimestamp(float(res.group(TS)))
        srcip = res.group(SRC)
        dstip = res.group(DST)
        sport = res.group(SPORT)
        dport = res.groupt(DPORT)
        proto = res.group(PROTO)
        if proto != "ICMP":
            size = int(res.group(SIZE))
    except TypeError:
        return
    return ts, srcip, dport, dstip, dport, size

def compute_ipt(last_ts, ts):
    cur = ts
    if last_ts:
        ipt = (cur - last_ts).total_seconds()
    else:
        ipt = 0
    return ipt

def read_dir(dirname, period):
    hourly_ps = []
    hourly_ipt = []
    timesize = timedelta(seconds=period)
    listdir = sorted(os.listdir(dirname))
    start = None
    stop = None
    last_ts = None
    ps_acc = 0
    ipt_acc = 0
    nb_pkt = 0
    for trace in listdir:
        filename = os.path.join(dirname, trace)
        with open(filename, "r") as f:
            for line in f:
                ts, src, sport, dst, dport, size = getdata(line)

                if not start:
                    start = ts
                    stop = start + timesize

                if ts > stop:
                    avg_ps = ps_acc/float(nb_pkt)
                    avg_ipt = ipt_acc/float(nb_pkt)
                    hourly_ps.append(avg_ps)
                    hourly_ipt.append(avg_ipt)
                    start = stop
                    stop = start + timesize
                    ps_acc = 0
                    ipt_acc = 0
                    nb_pkt = 0

                if size > 0:
                    if last_ts:
                        ipt_acc += compute_ipt(last_ts, ts)
                    nb_pkt += 1
                    ps_acc += size
                    last_ts = ts
    return np.array(hourly_ps), np.array(hourly_ipt)

def pad_array(smaller, larger):
    result = np.zeros(larger.shape)
    result[:smaller.shape[0],:smaller.shape[1]] = smaller
    return result

def main(realdir, gendirs, period):
    real_ps, real_ipt = read_dir(realdir, period)
    gens_ps = []
    gens_ipt = []
    for dirname in gendirs:
        ps, ipt = read_dir(dirname, period)
        if len(ps) > len(real_ps):
            real_ps = pad_array(real_ps, ps) 
            real_ipt = pad_array(real_ipt, ipt)
        elif len(real_ps) > len(ps):
            ps = pad_array(ps, real_ps) 
            ipt = pad_array(ipt, real_ipt) 
        gens_ps.append(ps)
        gens_ipt.append(ipt)

    fig = plt.figure()
    ax = fig.add_subplot(1, 1, 1)

    if len(real_ps) > len(gens_ps):
        t = np.arange(0, len(real_ps), 1)
    else:
        t = np.arange(0, len(gens_ps), 1)

    ax.plot(t, real_ps)
    for ps in gens_ps:
        ax.plot(t, gens_ps)

    plt.show()

    ax.plot(t, real_ipt)
    for ipt in gens_ipt:
        ax.plot(t, ipt)

    plt.show()

if __name__ == "__main__":
    main(realdir, gendirs, period)
