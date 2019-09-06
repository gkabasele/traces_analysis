import argparse
import os
import pdb
import math
import re
from datetime import datetime, timedelta
import warnings
from collections import OrderedDict
from scapy.all import *
import numpy as np
import matplotlib.pyplot as plt

IP_PROTO_TCP = 6
REG_FLOW =r"(?P<ts>(\d+\.\d+)) IP (?P<src>(?:\d{1,3}\.){3}\d{1,3})(\.(?P<sport>\d+)){0,1} > (?P<dst>(?:\d{1,3}\.){3}\d{1,3})(\.(?P<dport>\d+)){0,1}: (?P<proto>(tcp|TCP|udp|UDP|icmp|ICMP))( |, length )(?P<size>\d+){0,1}"

TS = "ts"
SRC = "src"
SPORT = "sport"
DST = "dst"
DPORT = "dport"
PROTO = "proto"
SIZE = "size"

np.seterr(all="warn")
warnings.filterwarnings("error")

class Stats(object):

    def __init__(self):
        self.ps = []
        self.ipt = []
        self.last = None

    def add(self, size, ts):
        self.ps.append(size)
        if self.last is not None:
            diff = ts - self.last
            self.ipt.append(diff)
        self.last = ts

def dt_to_msec(dt):
    epoch = datetime.utcfromtimestamp(0)
    return (dt - epoch).total_seconds() * 1000

def autocorr_coef(timeseries, t=1):
    try:
        if len(timeseries) > 1:
            lista = [i for i in timeseries[:-t]]
            listb = [i for i in timeseries[t:]]
            ex_val = np.mean(timeseries)
            if math.isnan(ex_val):
                pdb.set_trace()

            num = 0
            denum = 0
            for i in xrange(len(timeseries)):
                if i < len(lista):
                    num += (lista[i]-ex_val) * (listb[i] - ex_val)
                denum += (timeseries[i] - ex_val)**2
            
            if denum != 0:
                return float(num)/denum
    except Warning as w:
        print(w)

def autocorr(x, t=1):
    try:
        if len(x) > 2:
           return np.corrcoef(np.array([x[:-t], x[t:]]))[0, 1]
    except Warning as w:
        print(w)

def test_autocorr_coef():
    ts = [9.08, 12.63, 15.00, 20.73, 2.20, 18.00, 7.16, 18.28, 21.00, 19.68,
          15.54, 24.00, 16.10, 11.93, 27.00, 12.51, 20.04, 30.00, 12.41, 14.33,
          33.00, 22.11, 17.91, 36.00]

    print(autocorr(ts, 1))
    print(autocorr_coef(ts, 1))

def update_flow_pcap(pObj, flows):
    for pkt in pObj:
        if IP in pkt:
            srcip = pkt[IP].src
            dstip = pkt[IP].dst
            if pkt[IP].proto == IP_PROTO_TCP:
                proto = str(pkt[IP].proto)
                sport = str(pkt[TCP].sport)
                dport = str(pkt[TCP].dport)
                flow = (srcip, sport, proto, dstip, dport)
                ts = pkt.time
                size = len(pkt[TCP].payload)
                if size > 0:
                    if flow not in flows:
                        stat = Stats()
                        stat.last = ts
                        stat.ps.append(size)
                        flows[flow] = stat
                    else:
                        flows[flow].add(size, ts)

def update_flow_txt(f, flows, reg):
    for line in f:
        res = reg.match(line)
        src = res.group(SRC)
        dst = res.group(DST)
        sport = res.group(SPORT)
        dport = res.group(DPORT)
        proto = res.group(PROTO)
        ts = dt_to_msec(datetime.fromtimestamp(float(res.group(TS))))
        if proto != "ICMP":
            size = int(res.group(SIZE))
            if size > 0:
                flow = (src, sport, proto, dst, dport)
                if flow not in flows:
                    stat = Stats()
                    stat.last = ts
                    stat.ps.append(size)
                    flows[flow] = stat
                else:
                    flows[flow].add(size, ts)

def run(indir, mode="txt"):

    listdir = sorted(os.listdir(indir))
    flows = {}
    for trace in listdir:
        filename = os.path.join(indir, trace)
        if mode == "pcap":
            pObj = PcapReader(filename)
            update_flow_pcap(pObj, flows)
            pObj.close()
        elif mode == "txt":
            with open(filename, "r") as f:
                update_flow_txt(f, flows, re.compile(REG_FLOW))

    ac_per_flow = {}
    for k, v in flows.items():
        #ac_ps = autocorr_coef(v.ps)
        #ac_ipt = autocorr_coef(v.ipt)
        ac_ps = autocorr(v.ps)
        ac_ipt = autocorr(v.ipt)
        if ac_ps is not None and ac_ipt is not None:
            ac_per_flow[k] = (ac_ps, ac_ipt)
    return ac_per_flow

def main(realdir, gendir, mode):
    real_acs = run(realdir, mode)
    gen_acs = run(gendir, mode)

    pos_thresh = 0.2
    neg_thresh = -0.2

    r_ps = sorted([i[0] for i in real_acs.values()])
    g_ps = sorted([i[1] for i in gen_acs.values()])

    # relevant autocorr
    r_ps_rel = [x for x in r_ps if x > pos_thresh or x < neg_thresh]
    g_ps_rel = [x for x in g_ps if x > pos_thresh or x < neg_thresh]

    real_acs_ps = np.array(r_ps)
    gen_acs_ps = np.array(g_ps)

    r_n, r_bins, r_patches = plt.hist(real_acs_ps, bins=150, alpha=0.70,
                                      label="real")
    g_n, g_bins, g_patches = plt.hist(gen_acs_ps, bins=150, alpha=0.70,
                                      label="gen")

    print("Acc PS, real:{},{},{} gen:{},{},{}".format(len(real_acs_ps),
                                                      np.mean(real_acs_ps),
                                                      np.std(real_acs_ps),
                                                      len(gen_acs_ps),
                                                      np.mean(gen_acs_ps),
                                                      np.std(gen_acs_ps)))
    plt.axvline(x=pos_thresh, ls="--")
    plt.axvline(x=neg_thresh, ls="--")
    print("Real: {}, Gen:{}".format(len(r_ps_rel), len(g_ps_rel)))
    plt.legend(loc="upper right")
    plt.show()

    r_ipt = sorted([i[1] for i in real_acs.values()])
    g_ipt = sorted([i[1] for i in gen_acs.values()])

    r_ipt_rel = [x for x in r_ipt if x > pos_thresh or x < neg_thresh]
    g_ipt_rel = [x for x in g_ipt if x > pos_thresh or x < neg_thresh]

    real_acs_ipt = np.array(r_ipt)
    gen_acs_ipt = np.array(g_ipt)

    r_n, r_bins, r_patches = plt.hist(real_acs_ipt, 100, alpha=0.70,
                                      label="real")
    g_n, g_bins, g_patches = plt.hist(gen_acs_ipt, 100, alpha=0.70,
                                      label="gen")

    print("Acc IPT, real: {},{},{} gen:{},{},{}".format(len(real_acs_ipt),
                                                        np.mean(real_acs_ipt),
                                                        np.std(real_acs_ipt),
                                                        len(gen_acs_ps),
                                                        np.mean(gen_acs_ipt),
                                                        np.std(gen_acs_ipt)))
    plt.axvline(x=pos_thresh, ls="--")
    plt.axvline(x=neg_thresh, ls="--")
    print("Real: {}, Gen:{}".format(len(r_ipt_rel), len(g_ipt_rel)))
    plt.legend(loc="upper right")
    plt.show()

if __name__=="__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--gendir", action="store", type=str, dest="gendir")
    parser.add_argument("--realdir", action="store", type=str, dest="realdir")
    parser.add_argument("--mode", action="store", type=str, dest="mode")
    args = parser.parse_args()
    gendir = args.gendir
    realdir = args.realdir
    if args.mode is None:
        mode = "txt"
    else:
        mode = args.mode
    main(realdir, gendir, mode)
