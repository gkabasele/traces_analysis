import argparse
import os
import pdb
import re
from scapy.all import *
import numpy as np
import matplotlib.pyplot as plt

IP_PROTO_TCP = 6
REG_FLOW =r"(?P<ts>(\d+\.\d+)) IP (?P<src>(?:\d{1,3}\.){3}\d{1,3})(\.(?P<sport>\d+)){0,1} > (?P<dst>(?:\d{1,3}\.){3}\d{1,3})(\.(?P<dport>\d+)){0,1}: (?P<proto>(tcp|TCP|udp|UDP|icmp|ICMP))( |, length )(?P<size>\d+){0,1}"

SRC = "src"
SPORT = "sport"
DST = "dst"
DPORT = "dport"
PROTO = "proto"
SIZE = "size"

def autocorr_coef(timeseries, t=1):
    lista = [i for i in timeseries[:-t]]
    listb = [i for i in timeseries[t:]]
    
    ex_val = np.mean(timeseries)

    num = 0
    denum = 0
    for i in xrange(len(timeseries)):
        if i < len(lista):
            num += (lista[i]-ex_val) * (listb[i] - ex_val)
        denum += (timeseries[i] - ex_val)**2

    return float(num)/denum


def autocorr(x, t=1):
    return np.corrcoef(np.array([x[:-t], x[t:]]))[0, 1]

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
                if flow not in flows:
                    flows[flow] = [pkt[IP].len]
                else:
                    flows[flow].append(pkt[IP].len)

def update_flow_txt(f, flows, reg):
    for line in f:
        res = reg.match(line)
        src = res.group(SRC)
        dst = res.group(DST)
        sport = res.group(SPORT)
        dport = res.group(DPORT)
        proto = res.group(PROTO)
        size = 0
        if proto != "ICMP":
            size = int(res.group(SIZE))
        flow = (src, sport, proto, dst, dport) 
        if flow not in flows:
            flows[flow]= [size]
        else:
            flows[flow].append(size)
        
def run(indir, mode="txt"):

    listdir = sorted(os.listdir(indir))
    flows = {}
    for trace in listdir:
        filename = os.path.join(indir, trace)
        if mode == "txt":
            pObj = PcapReader(filename)         
            update_flow_pcap(pObj, flows)
            pObj.close()
        elif mode == "pcap":
            with open(filename, "r") as f:
                update_flow_txt(f, flows, re.compile(REG_FLOW))

    ac_per_flow = {}
    
    for k, v in flows.items():
        ac_per_flow[k] = autocorr_coef(v)
    return ac_per_flow

def main(realdir, gendir):
    real_acs = run(realdir)
    gen_acs = run(gendir)

    r_n, r_bins, r_patches = plt.hist(real_acs.values(), 100, alpha=0.70)
    g_n, g_bins, g_patches = plt.hist(gen_acs.values(), 100, alpha=0.70)

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
        mode = "pcap"
    main(realdir, gendir, mode)
