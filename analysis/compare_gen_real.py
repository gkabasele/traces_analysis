#!/usr/bin/env python

import matplotlib.pyplot as plt
import matplotlib as mpl
import math
import numpy as np
import scipy as sp
import os 
import sys
import argparse
import functools
import struct
import operator
import time
import datetime
from collections import Counter
from bisect import bisect_left
from numpy import cumsum
from scipy import stats as sts

UDP = 17
TCP = 6

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-gfile", type=str, dest="gfile", action="store",
                        help="input file containing the stats of generated trace")
    parser.add_argument("-rfile", type=str,dest= "rfile", action="store",
                        help="input file containing the stats of real trace")
    parser.add_argument("-d", type=str, dest="directory", action="store", help="directory where to output the plots")
    args = parser.parse_args()


hmi_port = ["50000", "135", "445"]
gateways_port = ["2499"]
web_port = ["80", "889", "443", "53"] 
netbios_port = ["137", "138"]
snmp_port = ["161", "162"]
rpc_port = ["50540", "54540", "55844", "49885", "58658", "56427", "62868", "59303", "53566"]  

def compare_cdf(data_a, data_b, title, legend_a, legend_b):
    data_a_sorted = sorted(data_a)
    data_b_sorted = sorted(data_b)

    fig = plt.figure()
    ax = fig.add_subplot(1, 1, 1)

    pfa = 1. * np.arange(len(data_a_sorted)) / (len(data_a_sorted) - 1)
    pfb = 1. * np.arange(len(data_b_sorted)) / (len(data_b_sorted) - 1)
    inc_a, = ax.plot(data_a_sorted, pfa, label=legend_a)
    inc_b, = ax.plot(data_b_sorted, pfb, label=legend_b)
    plt.legend(handles=[inc_a, inc_b], loc='upper center')
    plt.title(title)
    plt.show()


def plot_cdf(filename, values, labels, divs, xlabel, ylabel, title, min_x, max_x): 
    samples = []
    legends = []
    for i, val in enumerate(values):
        if divs[i] == 1:
            samples.append(np.sort(val))
        else:
            data = list(map(lambda x: x/float(divs[i]), val))
            tmp = np.sort(data)
            samples.append(tmp)

    plt.subplot(111)
    plt.xlabel(xlabel)
    plt.ylabel(ylabel)
    plt.title(title)

    for i,val in enumerate(samples):
        yvals = 1. * np.arange(len(val))/(len(val) - 1)
        #print(val[::5000])
        #print(yvals[::5000])
        inc, = plt.plot(val, yvals, label=labels[i])
        plt.xscale("log")
        plt.xlim(min_x, max_x)
        legends.append(inc)
    plt.legend(handles=legends, loc='upper center')
    plt.savefig(filename)
    plt.close()


def plot_hourly(filename, stats, labels, xlabel, ylabel, title, div=1, log=False):
    plt.subplot(111)
    legends = []
    for i, stat in enumerate(stats):
        if div == 1:
            out, = plt.plot(range(1, len(stat) + 1), stat, label=labels[i])
        else:
            tmp = list(map(lambda x: x/float(div), stat))
            out, = plt.plot(range(1, len(stat) + 1), tmp, label=labels[i])

        legends.append(out)
    plt.legend(handles=legends, loc='upper center')
    if log:
        plt.yscale("log", basey=10)
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

def plot_pdf(filename, values, xlabel, title, num=50, bins=50):
    samples = np.array(values)
    mean = np.mean(samples)
    var = np.var(samples)
    std = np.sqrt(var)
    x = np.linspace(min(samples), max(samples), num)
    n, bins, patches = plt.hist(samples, bins, density=True, alpha=0.75)
    plt.xlabel(xlabel)
    plt.title(title)
    plt.savefig(filename)
    plt.close()

def divide_by(values, div):
    if div != 1:
        v = list(map(lambda x: x/div, values))
    else:
        v = values
    return values

def plot_hist(filename, values, xlabel, title, div=1, log=False):
    v = divide_by(values, div)
    data = np.sort(v)
    counts, bin_edges = np.histogram(data, bins=100, density=True)
    cdf = np.cumsum(counts)
    cdf.insert(0,0)
    bin_edges.insert(0,0)
    plt.plot(bin_edges[1:], cdf/cdf[-1])
    plt.ticklabel_format(useOffset=False, style='plain')
    if log:
        plt.xscale=("log")
    plt.xlabel(xlabel)
    plt.ylabel("CDF")
    plt.title(title)
    plt.savefig(filename)
    plt.close()


def main(gfile, rfile, directory):

    sizes = []
    durations = []
    nbr_packets = []

    for index, filename in enumerate([gfile, rfile]):
        f = open(filename, "r")

        # inter = avg inter arrival
        all_inter_tcp = []
        all_size_tcp = []
        all_dur_tcp = []

        all_inter_udp = []
        all_size_udp = []
        all_dur_udp = []

        total_size_array = [] 
        pkts_array =  []

        hmi_to_mtu_size = []
        mtu_to_gateway_size = []
        web_size = []
        netbios_size = []
        snmp_size = []

        hmi_to_mtu_pkt = []
        mtu_to_gateway_pkt = []
        web_pkt = []
        netbios_pkts = []
        snmp_pkts = []
        
        flows = set() 

        ip_addresses = set()

        hmis = set()

        gateways = set()
        rpc_size = []
        rpc_pkts = []


        size_repartition = {}
        pkts_repartition = {}

        hmi_mtu = 0

        pc = 0


        for l,line in enumerate(f.readlines()):
            if l != 0:
                (srcip, destip, sport, dport, proto, tgh, avg, max_size, 
                        total_size, wire_size, pkts, first, last, interarrival, duration) = line.split("\t")

                flows.add((srcip, destip, sport, dport, proto)) 
                ip_addresses.add(srcip)
                ip_addresses.add(destip)

                if sport in size_repartition:
                    size_repartition[sport] += int(total_size)
                else:
                    size_repartition[sport] = int(total_size)

                if sport in pkts_repartition:
                    pkts_repartition[sport] += int(pkts)
                else:
                    pkts_repartition[sport] = int(pkts)

                total_size_array.append(int(total_size))
                pkts_array.append(int(pkts))

                if int(proto) == TCP:
                    all_inter_tcp.append(int(interarrival))
                    all_size_tcp.append(int(total_size))
                    all_dur_tcp.append(int(duration))

                    if sport in hmi_port or dport in hmi_port:
                        hmi_to_mtu_size.append(int(total_size))
                        hmi_to_mtu_pkt.append(int(pkts))

                        hmi_mtu += int(total_size)

                        # Port open on the mtu
                        if sport in hmi_port:
                            hmis.add(srcip)
                        else:
                            hmis.add(destip)


                    if sport in gateways_port or dport in gateways_port:
                        mtu_to_gateway_size.append(int(total_size))
                        mtu_to_gateway_pkt.append(int(pkts))

                        if sport in gateways_port:
                            gateways.add(srcip)
                        else:
                            gateways.add(destip)

                    if sport in web_port or dport in web_port:
                        web_size.append(int(total_size))
                        web_pkt.append(int(pkts))

                    if sport in rpc_port or dport in rpc_port : 
                        hmi_to_mtu_size.append(int(total_size))
                        hmi_to_mtu_pkt.append(int(pkts))
                        
                elif int(proto) == UDP:
                    all_inter_udp.append(int(interarrival))
                    all_size_udp.append(int(total_size))
                    all_dur_udp.append(int(duration))

                    if sport in web_port or dport in web_port:
                        web_size.append(int(total_size))
                        web_pkt.append(int(pkts))

                    if sport in netbios_port or dport in netbios_port:
                        netbios_size.append(int(total_size))
                        netbios_pkts.append(int(pkts))


        total_size_rep = sum(size_repartition.values())
        for k in size_repartition:
            size_repartition[k] = size_repartition[k]/float(total_size_rep)

        sorted_size = sorted(size_repartition.items(), key=operator.itemgetter(1))

        np_size_array = np.array(total_size_array)
        np_pkts_array = np.array(pkts_array)

        np_hmi_size = np.array(hmi_to_mtu_size)
        np_hmi_pkt = np.array(hmi_to_mtu_pkt)

        np_mtu_size = np.array(mtu_to_gateway_size)
        np_mtu_pkt = np.array(mtu_to_gateway_pkt)

        np_web_size = np.array(web_size)
        np_web_pkt = np.array(web_pkt)

        np_netbios_size = np.array(netbios_size)
        np_netbios_pkt = np.array(netbios_pkts)

        stat_file = directory + "/" + "stats.txt"
        with open(stat_file, "a") as f:
            if index == 0:
                f.write("++Summary Generated trace++\n")
            else:
                f.write("++Summary Real trace++\n")
            f.write("-------\n")
            f.write("IP Addr:{}\n".format(len(ip_addresses)))
            f.write("HMI:{}\n".format(len(hmis)))
            f.write("Gateway:{}\n".format(len(gateways)))
            f.write("flow:{}\n".format(len(flows)))
            f.write("min size:{}\n".format(np.min(np_size_array)))
            f.write("avg size:{}\n".format(np.average(np_size_array)))
            f.write("max size:{}\n".format(np.max(np_size_array)))

            tmp_total = np.sum(np_size_array)
            f.write("Total size: {}\n".format(tmp_total))
            f.write("HMI size:{} ({}%)\n".format(np.sum(np_hmi_size), np.sum(np_hmi_size)/float(tmp_total)))
            f.write("MTU size:{} ({}%)\n".format(np.sum(np_mtu_size), np.sum(np_mtu_size)/float(tmp_total)))
            f.write("Web size:{} ({}%)\n".format(np.sum(np_web_size), np.sum(np_web_size)/float(tmp_total)))
            f.write("Netbios size:{} ({}%)\n".format(np.sum(np_netbios_size), np.sum(np_netbios_size)/float(tmp_total)))
            f.write("min pkt:{}\n".format(np.min(np_pkts_array)))
            f.write("avg pkt:{}\n".format(np.average(np_pkts_array)))
            f.write("max pkt:{}\n".format(np.max(np_pkts_array)))

            tmp_total = np.sum(np_pkts_array)
            f.write("Total pkt: {}\n".format(tmp_total))
            f.write("HMI pkt:{} ({}%)\n".format(np.sum(np_hmi_pkt), np.sum(np_hmi_pkt)/float(tmp_total)))
            f.write("MTU pkt:{} ({}%)\n".format(np.sum(np_mtu_pkt), np.sum(np_mtu_pkt)/float(tmp_total)))
            f.write("Web pkt:{} ({}%)\n".format(np.sum(np_web_pkt), np.sum(np_web_pkt)/float(tmp_total)))
            f.write("Netbios pkt:{} ({}%)\n".format(np.sum(np_netbios_pkt), np.sum(np_netbios_pkt)/float(tmp_total)))
            f.write("-----------\n\n")


        sizes.append(all_size_tcp + all_size_udp)
        durations.append(all_dur_tcp + all_dur_udp)
        nbr_packets.append(pkts_array)
        f.close()
    compare_cdf(sizes[0], sizes[1], "size", "gen", "real")
    compare_cdf(durations[0], durations[1], "duration", "gen", "real")
    compare_cdf(nbr_packets[0], nbr_packets[1], "nbr packets", "gen", "real")

def read(_type, readsize, f, index):
    return index+readsize, struct.unpack(_type, f.read(readsize))[0]

if __name__=="__main__":
    main(args.gfile, args.rfile, args.directory)