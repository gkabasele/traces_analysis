import re
import os
import pdb
import matplotlib.pyplot as plt
import numpy as np
from datetime import datetime

from autocorr import *

realdir = "../generator/ids/2hours_real"
gendir = "../generator/ids/2hour_leg"


r_fkey = ("192.168.246.45", "2499", "tcp", "192.168.246.228", "55434")

g_fkey = ("10.0.0.3", "2499", "tcp", "10.0.0.1", "55434")

dist_reg_flow = {
                    'expon': './exponential.txt',
                    'norm': './normal.txt',
                    'gamma': './gamma.txt',
                    'weibull': './weibull.txt'
                }
dist_reg = {
             'cauchy': './cauchy.txt',
           }

def plot_cdf(data, marker, lab):
    x = np.sort(data)
    n = x.size
    y = np.arange(1, n+1)/float(n)
    plt.plot(x, y, marker,label=lab)

def readdir(indir):
    listdir = sorted(os.listdir(indir))
    flows = {}
    for trace in listdir:
        filename = os.path.join(indir, trace)
        with open(filename, "r") as f:
            update_flow_txt(f, flows, re.compile(REG_FLOW))
    return flows

def readfile_flow(f, flows):
    reg = re.compile(REG_FLOW)
    for line in f:
        res = reg.match(line)
        if res is not None:
            src = res.group(SRC)
            dst = res.group(DST)
            sport = res.group(SPORT)
            dport = res.group(DPORT)
            proto = res.group(PROTO)
            ts = dt_to_msec(datetime.fromtimestamp(float(res.group(TS))))
            if proto != "ICMP":
                size = int(res.group(SIZE))
                if dport == '8999' and size > 0:
                    flow = (src, sport, proto, dst, dport)
                    if flow not in flows:
                        stat = Stats()
                        stat.last = ts
                        stat.counter = 1
                        stat.ps.append(size)
                        stat.start = ts
                        stat.end = ts + ONE_SEC
                        flows[flow] = stat
                    else:
                        flows[flow].add(size, ts)

def readfile(f, flows, size):
    reg = re.compile(REG)
    for line in f:
        res = reg.match(line)
        if res is not None:
            src = res.group(SRC)
            dst = res.group(DST)
            sport = res.group(SPORT)
            dport = res.group(DPORT)
            flag = res.group(FLAG)
            ts = dt_to_msec(datetime.fromtimestamp(float(res.group(TS))))
            if dport == '8999' and (flag == '[P.]' or flag == '[P]'):
                flow = (src, sport, 'tcp', dst, dport)
                if flow not in flows: 
                    stat = Stats()    
                    stat.last = ts
                    stat.counter = 1
                    stat.ps.append(size)
                    stat.start = ts
                    stat.end = ts + ONE_SEC
                    flows[flow] = stat
                else:
                    flows[flow].add(size, ts)

def get_primary_flow(flows):
    primary_flow = None
    minval = 0
    for k, v in flows.items():
        val = len(v.ipt) 
        if minval == 0 or val < minval:
            primary_flow = k
            minval = val
    return primary_flow

def process_list(data, max_val):
    for i in range(len(data)):
        if data[i] > max_val:
            data[i] = max_val

def getDist():
    flows_r = readdir(realdir)
    flows_g = readdir(gendir)
    st_r = flows_r[r_fkey]
    st_g = flows_g[g_fkey]

    plot_cdf(st_r.ipt, "-","real")
    plot_cdf(st_g.ipt, "--","gen")

    max_val = np.max(st_r.ipt)

    markers = ["-.", ":", "-", "--"]
    i = 0
    for k, v in dist_reg_flow.items():
        with open(v, "r") as f:
            flows = {}
            readfile_flow(f, flows)
            primary_flow = get_primary_flow(flows)
            s = flows[primary_flow]
            process_list(s.ipt, max_val)
            plot_cdf(s.ipt, markers[i], k)
        i = (i + 1) % len(markers)

    for k, v in dist_reg.items():
        with open(v, "r") as f:
            flows = {}
            readfile(f, flows, 79)
            primary_flow = get_primary_flow(flows)
            s = flows[primary_flow]
            process_list(s.ipt, max_val)
            plot_cdf(s.ipt, markers[i], k)
        i = (i + 1) % len(markers)

    plt.xlabel("Inter-Pacekt Time(ms)")
    plt.ylabel("P(X<=x)")
    plt.title("IPT CDF per distribution")
    plt.legend(loc="upper right")
    plt.show()

getDist()
