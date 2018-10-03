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

parser = argparse.ArgumentParser()
parser.add_argument("-f", type=str, dest="filename", action="store", help="input file containing the stats")
parser.add_argument("-t", type=str, dest="timeseries", action="store", help="input file containing the timeseries")
parser.add_argument("-c", type=str, dest="connections", action="store", help="input file containing information from connections")
parser.add_argument("-d", type=str, dest="directory", action="store", help="directory where to output the plots")
args = parser.parse_args()

def plot_cdf(filename, tcp, udp, xlabel, ylabel, title, l1, l2, div1=1, div2=1):
    if div1 == 1:
        sorted_tcp = np.sort(tcp)
    else:
        sorted_tcp = np.sort(list(map(lambda x: x/div1, tcp)))

    if div2 == 1:
        sorted_udp = np.sort(udp)
    else:
        sorted_udp = np.sort(list(map(lambda x: x/div2, udp)))

    plt.subplot(111)
    p = 1. * np.arange(len(tcp))/(len(tcp) - 1)
    q = 1. * np.arange(len(udp))/(len(udp) - 1)
    plt.xlabel(xlabel)
    plt.ylabel(ylabel)
    plt.title(title)
    inc, = plt.plot(sorted_tcp, p, label=l1)
    out, = plt.plot(sorted_udp, q, label=l2)
    plt.legend(handles=[out, inc], loc='upper center')
    plt.savefig(filename)
    plt.close()

def plot_hourly(filename, stats, labels, xlabel, ylabel, title):
    plt.subplot(111)
    legends = []
    for i, stat in enumerate(stats):
        out, = plt.plot(range(1, len(stat) + 1), stat, label= labels[i])
        legends.append(out)
    plt.legend(handles=legends, loc='upper center')
    plt.xlabel(xlabel)
    plt.ylabel(ylabel)
    plt.title(title)
    plt.savefig(filename)
    plt.close()

def plot_distribution(filename, stat, title):

    plt.hist(stat)
    plt.title(title)
    plt.savefig(filename)
    plt.close()

def main(filename, timeseries, conn_info, directory):

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

    plot_cdf(directory + "/" + "interarrival.png", all_dur_tcp, all_dur_udp, "Inter Arrival (ms)", "CDF", "CDF of inter arrival", "TCP", "UDP")

    plot_cdf(directory + "/" + "flow_size.png", all_size_tcp, all_dur_udp, "Flow Size (KB)", "CDF","CDF of flow size", "TCP", "UDP", 1000, 1000) 

    plot_cdf(directory +"/" + "duration.png", all_dur_tcp, all_dur_udp, "Duration (Min)", "CDF", "CDF of duration", "TCP", "UDP", 60000, 60000)

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

    plot_hourly(directory + "/" + "nbr_pkt.png", list_pkts, ["Server->FD", "FD->Server"], "Hour", "#PKTS", "Nbr Pkts per hour")

    plot_hourly(directory + "/" + "size.png", list_size, ["Server->FD", "FD->Server"], "Hour", "Bytes", "Bytes per hour")

    
    res = np.array(sorted_bna_inter)
    plot_distribution(directory + "/" + "inter_dist.png", res, "Interrival Distribution")

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

    plot_hourly(directory + "/" + "new_flow.png", [tcp_new_conn, udp_new_conn, bna_new_conn], ["TCP", "UDP", "HVAC"], "Hour", "#Flow", "Flow discovery per hour")



if __name__=="__main__":
    main(args.filename, args.timeseries, args.connections, args.directory)
