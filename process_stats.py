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
parser.add_argument("-c", type=str, dest="connections", action="store", help="input file containing information from connections")
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



def main(filename, timeseries, conn_info):

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
    conn = open(conn_info, "r")

    # inter = avg inter arrival
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



    # Timerseries analysis
    flow_labels = []
    list_pkts = []
    list_size = []

    bna_inter = []

    for l, line in enumerate(ts.readlines()):
        if l % 4 == 0:
            (flow, proto) = line.split()
            flow_labels.append(flow)
        elif (l + 3) % 4 == 0:
            nbr_pkt = line.split("\t")
            list_pkts.append(nbr_pkt)
        elif (l + 2) % 4 == 0:
            size = line.split("\t")
            list_size.append(size)
        elif (l + 1) % 4 == 0:
            bna_inter = [ int(x) for x in line.split("\t")]

    sorted_bna_inter = sorted(bna_inter)

    plt.subplot(111)
    out, = plt.plot(range(1, len(list_pkts[0]) + 1), list_pkts[0], label="Server->FD")
    inc, = plt.plot(range(1, len(list_pkts[1]) + 1), list_pkts[1], label="FD->Server")
    plt.legend(handles=[out, inc])
    plt.axis([1,2, 0, 700])
    plt.xlabel("Hour")
    plt.ylabel("#PKTS")
    plt.title("Nbr Pkts per hour")
    plt.show()

    #plt.plot(range(1, len(list_pkts[0]) + 1 ),list_pkts[0],range(1, len(list_pkts[1]) + 1), list_pkts[1])
    #plt.axis([1, 2, 0, 700])
    #plt.show()


    plt.subplot(111)
    out, = plt.plot(range(1, len(list_size[0]) + 1), list_size[0], label="Server->FD")
    inc, = plt.plot(range(1, len(list_size[1]) + 1), list_size[1], label="FD->Server")
    plt.legend(handles=[out, inc])
    plt.axis([1, 2, 0, 5000])
    plt.xlabel("Hour")
    plt.ylabel("Bytes")
    plt.title("Bytes per hour")
    plt.show()

    #plt.plot(range(1, len(list_size[0]) + 1), list_size[0], range(1, len(list_size[1]) + 1), list_size[1])
    #plt.axis([1, 2, 0, 5000]) 
    #plt.show()



    res = np.array(sorted_bna_inter)
    plt.hist(res, bins= [500*x for x in range(0,21)])
    plt.title("Distribution of interarrival BNA")
    plt.show()

    # New connections by hour
    label = []
    tcp_new_conn = []
    udp_new_conn = []
    bna_new_conn = []

    res = [tcp_new_conn, udp_new_conn, bna_new_conn]
    for l, line in enumerate(conn.readlines()):
        if l % 2 ==  0:
            label.append(line) 
        elif l == 1:
            tcp_new_conn = line.split("\t")
        elif l == 3:
            udp_new_conn = line.split("\t")
        elif l == 5:
            bna_new_conn = line.split("\t")

    plt.subplot(111)
    tcp, = plt.plot(range(1, len(tcp_new_conn) + 1), tcp_new_conn, label="TCP")
    udp, = plt.plot(range(1, len(udp_new_conn) + 1), udp_new_conn, label="UDP")
    out, = plt.plot(range(1, len(bna_new_conn) + 1), bna_new_conn, label="FD->Server")
    plt.legend(handles=[tcp, udp, out])
    plt.xlabel("Hour")
    plt.ylabel("#Connections")

    #plt.plot(range(1, len(tcp_new_conn) + 1), tcp_new_conn, range(1, len(udp_new_conn) + 1), udp_new_conn, range(1, len(bna_new_conn) + 1), bna_new_conn)
    plt.title("New observed connections by hour")    
    plt.show()



if __name__=="__main__":
    main(args.filename, args.timeseries, args.connections)
