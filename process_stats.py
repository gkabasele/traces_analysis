#!/usr/bin/env python

import matplotlib.pyplot as plt
import matplotlib as mpl
import numpy as np
import scipy as sp
import os 
import sys
import argparse
import functools
from numpy import cumsum
from scipy import stats as sts
UDP = 17
TCP = 6

parser = argparse.ArgumentParser()
parser.add_argument("-f", type=str, dest="filename", action="store", help="input file containing the stats")
parser.add_argument("-t", type=str, dest="timeseries", action="store", help="input file containing the timeseries")
parser.add_argument("-c", type=str, dest="connections", action="store", help="input file containing information from connections")
parser.add_argument("-d", type=str, dest="directory", action="store", help="directory where to output the plots")
args = parser.parse_args()

#def plot_cdf(filename, tcp, udp, xlabel, ylabel, title, l1, l2, div1=1, div2=1):
def plot_cdf(filename, values, labels, divs, xlabel, ylabel, title): 
    samples = []
    legends = []
    for i, val in enumerate(values):
        if divs[i] == 1:
            samples.append(np.sort(val))
        else:
            samples.append(np.sort(list(map(lambda x: x/divs[i], val))))

    plt.subplot(111)
    plt.xlabel(xlabel)
    plt.ylabel(ylabel)
    plt.title(title)
    for i,val in enumerate(samples):
        p = 1. * np.arange(len(val))/(len(val) - 1)
        inc, = plt.plot(val, p, label=labels[i])
        legends.append(inc)
    plt.legend(handles=legends, loc='upper center')
    plt.savefig(filename)
    plt.close()

def plot_hourly(filename, stats, labels, xlabel, ylabel, title, div=1):
    plt.subplot(111)
    legends = []
    for i, stat in enumerate(stats):
        if div == 1:
            out, = plt.plot(range(1, len(stat) + 1), stat, label=labels[i])
        else:
            tmp = list(map(lambda x: x/div, stat))
            out, = plt.plot(range(1, len(stat) + 1), tmp, label=labels[i])

        legends.append(out)
    plt.legend(handles=legends, loc='upper center')
    plt.xlabel(xlabel)
    plt.ylabel(ylabel)
    plt.title(title)
    plt.savefig(filename)
    plt.close()

def plot_distribution(filename, stat, xlabel, title, bins=None):
    h, x1 = np.histogram(stat, bins= 300, normed= True, density=True)
    plt.title(title)
    plt.xlabel(xlabel)
    plt.plot(x1[1:], h)
    plt.savefig(filename)
    plt.close()

def plot_pdf(filename, values, xlabel, title):
    samples = np.array(values)
    mean = np.mean(samples)
    var = np.var(samples)
    std = np.sqrt(var)
    x = np.linspace(min(samples), max(samples), 50)
    #y_pdf = sts.lognorm.fit(x, 0.5) 
    #l1, = plt.plot(x, y_pdf) 
    n, bins, patches = plt.hist(samples, 50, density=True, alpha=0.75)
    plt.xlabel(xlabel)
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

    plot_cdf(directory + "/" + "interarrival.png", [all_dur_tcp, all_dur_udp],["TCP", "UDP"], [1000,1000] ,"Inter Arrival (ms)", "CDF", "CDF of inter arrival")

    plot_cdf(directory + "/" + "flow_size.png", [all_size_tcp, all_dur_udp], ["TCP", "UDP"], [1000,1000],"Flow Size (kB)", "CDF","CDF of flow size") 

    plot_cdf(directory +"/" + "duration.png", [all_dur_tcp, all_dur_udp], ["TCP", "UDP"], [360000, 360000],"Duration (Hour)", "CDF", "CDF of duration")

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
            list_pkts.append([int(x) for x in nbr_pkt])
        elif (l + 2) % 4 == 0:
            size = line.split("\t")
            list_size.append([int(x) for x in size])
        elif (l + 1) % 4 == 0:
            bna_inter = [ int(x) for x in line.split("\t")]

    sorted_bna_inter = sorted(bna_inter)

    plot_hourly(directory + "/" + "nbr_pkt.png", list_pkts, ["Gateway->Server", "Server->Gateway"], "Hour", "#PKTS", "Nbr Pkts per hour")

    plot_hourly(directory + "/" + "size.png", list_size, ["Gateway->Server", "Server->Gateway"], "Hour", "kB", "Kilobytes per hour", 1000)

    
    res = np.array(sorted_bna_inter)
    bins = None
    plot_pdf(directory + "/" + "inter_pdf.png", res, "Time(ms)","PDF of Inter arrival packet")
    plot_cdf(directory + "/" + "inter_cdf.png", [res], ["HVAC"], [1,1], "Time(ms)", "CDF", "CDF of Inter arrival packet") 

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
            tcp_new_conn = [int(x) for x in line.split("\t")]
        elif l == 3:
            udp_new_conn = [int(x) for x in line.split("\t")]
        elif l == 5:
            bna_new_conn = [int(x) for x in line.split("\t")]

    plot_hourly(directory + "/" + "new_flow.png", [tcp_new_conn, udp_new_conn, bna_new_conn], ["TCP", "UDP", "HVAC"], "Hour", "#Flow", "Flow discovery per hour")

    f.close()
    ts.close()
    conn.close()

if __name__=="__main__":
    main(args.filename, args.timeseries, args.connections, args.directory)
