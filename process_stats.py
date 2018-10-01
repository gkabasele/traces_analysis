#!/usr/bin/env python

import matplotlib.pyplot as plt
import matplotlib as mpl
import numpy as np
import os 
import sys
import argparse
import functools
from numpy import cumsum

UDP = 17
TCP = 6


@functools.total_ordering
class InterArrivalGroup(object):

    def __init__(self, ident, lower, upper):
        self.ident = ident
        self.lower = lower
        self.upper = upper

    def __eq__(self, other):
        return (self.ident == other.ident and self.lower == other.lower 
                and self.upper == other.upper)
    def __lt__(self, other):
        return (self.lower, self.upper) < (other.lower, other.upper)


parser = argparse.ArgumentParser()
parser.add_argument("-f", type=str, dest="filename", action="store", help="input file containing the stats")
parser.add_argument("-t", type=str, dest="timeseries", action="store", help="input file containing the timeseries")
args = parser.parse_args()

def plot_cdf(res, label, divider=1):
    if divider == 1:
        sorted_res = np.sort(res)
    else:
        sorted_res = np.sort(list(map(lambda x: x/divider, res)))

    p = 1. * np.arange(len(res))/(len(res) - 1)
    plt.xlabel(label)
    plt.plot(sorted_res, p)
    plt.show()



def main(filename, timeseries):

    dist = {
        0       :   0,
        50      :   0,
        100     :   0,
        150     :   0,
        200     :   0,
        500     :   0,
        1000    :   0,
        1500    :   0,
        2000    :   0,
        2500    :   0,
        5000    :   0,
        10000   :   0,
        20000   :   0
    }

    f = open(filename, "r")
    ts = open(timeseries, "r")
    all_inter_tcp = []
    all_size_tcp = []
    all_dur_tcp = []

    all_inter_udp = []
    all_size_udp = []
    all_dur_udp = []

    x_value = sorted(dist.keys())
    
    for l,line in enumerate(f.readlines()):
        if l != 0:
            (srcip, destip, sport, dport, proto, tgh, avg, max_size, 
                    total_size, wire_size, pkts, first, last, interarrival, duration) = line.split("\t")
            if int(proto) == TCP:
                all_inter_tcp.append(int(interarrival))
                all_size_tcp.append(int(total_size))
                all_dur_tcp.append(int(duration))
            elif int(proto) == UDP:
                all_inter_udp.append(int(interarrival))
                all_size_udp.append(int(total_size))
                all_dur_udp.append(int(duration))

            for i in range(len(x_value)- 1):
                lower = x_value[i]
                upper = x_value[i+1]
                if int(interarrival) in range(lower, upper):
                    dist[lower] += 1


    y_value = [ dist[v] for v in x_value ] 


    # Inter arrival 
    plot_cdf(all_inter_tcp, "Avg inter arrival (ms)")
    plot_cdf(all_inter_udp, "Avg inter arrival (ms)")

    # Total byte
    plot_cdf(all_size_tcp, "Flow Size (KB)", 1000)
    plot_cdf(all_size_udp, "Flow Size (KB)", 1000)
    

    # Duration
    plot_cdf(all_dur_tcp, "Duration (Min)", 60000)
    plot_cdf(all_dur_udp, "Duration (Min)", 60000)


    flow_labels = []
    list_pkts = []
    list_size = []
   
    for l, line in enumerate(ts.readlines()):
        if l % 3 == 0:
            (flow, proto) = line.split()
            flow_labels.append(flow)
        elif (l + 2) % 3 == 0:
            nbr_pkt = line.split("\t")
            list_pkts.append(nbr_pkt)
        elif (l + 1) % 3 == 0:
            size = line.split("\t")
            list_size.append(size)

    plt.plot(range(1, len(list_pkts[0]) + 1 ),list_pkts[0],range(1, len(list_pkts[1]) + 1), list_pkts[1])
    plt.axis([1, 2, 0, 700])
    plt.show()

    plt.plot(range(1, len(list_size[0]) + 1), list_size[0], range(1, len(list_size[1]) + 1), list_size[1])
    plt.axis([1, 2, 0, 5000]) 
    plt.show()

if __name__=="__main__":
    main(args.filename, args.timeseries)
