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
import pdb
import datetime
from collections import Counter, namedtuple
from bisect import bisect_left
from numpy import cumsum
from scipy import stats as sts

UDP = 17
TCP = 6

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--gfile", type=str, dest="gfile", action="store",
                        help="input file containing the stats of generated trace")
    parser.add_argument("--rfile", type=str,dest= "rfile", action="store",
                        help="input file containing the stats of real trace")
    parser.add_argument("--gipt", type=str, dest="gipt", action="store",
                        help="input file containing the IPT of generated trace")
    parser.add_argument("--ript", type=str, dest="ript", action="store",
                        help="input file containing the IPT of real trace")
    parser.add_argument("--sim", type=str, dest="sim", action="store")
    parser.add_argument("--dir", type=str, dest="directory", action="store", help="directory where to output the plots")
    args = parser.parse_args()


hmi_port = ["50000", "135", "445"]
gateways_port = ["2499"]
web_port = ["80", "889", "443", "53"] 
netbios_port = ["137", "138"]
snmp_port = ["161", "162"]
rpc_port = ["50540", "54540", "55844", "49885", "58658", "56427", "62868", "59303", "53566"]  

def compare_cdf(data_a, data_b, title, legend_a, legend_b, xlabel, ylabel):
    data_a_sorted = sorted(data_a)
    data_b_sorted = sorted(data_b)

    fig = plt.figure()
    ax = fig.add_subplot(1, 1, 1)

    pfa = 1. * np.arange(len(data_a_sorted)) / (len(data_a_sorted) - 1)
    pfb = 1. * np.arange(len(data_b_sorted)) / (len(data_b_sorted) - 1)
    plt.xlabel(xlabel)
    plt.ylabel(ylabel)
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

def display_flowstat(stats):
    for k,v in stats.iteritems():
        if len(v) % 2 == 0:
            length = 0
            while length < len(v):
                gen, real = v[length:length+2]
                diff = "size: {}, pkts: {},  thg: {}, dur: {}".format(
                    gen.size - real.size,
                    gen.pkts - real.pkts,
                    gen.thg - real.thg,
                    gen.dur - real.dur)
                print "{} : {}".format(k, diff)
                length += 2

def convert_value(val):
    try:
        return float(val)
    except ValueError:
        return val

def compare_with_simulation(gfile, rfile):

    sizes = []
    durations = []
    nbr_packets = []
    total_thg_averages = []
    thg_averages = []

    flows_difference = {}

    FlowStats = namedtuple('FlowStats', ['size', 'pkts', 'thg', 'dur'])
    for index, filename in enumerate([gfile, rfile]):
        f = open(filename, "r")
        all_inter_tcp = []
        all_size_tcp = []
        all_dur_tcp = []

        all_inter_udp = []
        all_size_udp = []
        all_dur_udp = []

        total_size_array = [] 
        total_pkt_array = []
        pkts_array = []

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

        payload_thg_avg = []
        total_thg_avg = []

        flows = set() 

        ip_addresses = set()

        hmis = set()

        gateways = set()
        rpc_size = []
        rpc_pkts = []


        size_repartition = {}
        pkts_repartition = {}

        hmi_mtu = 0

        for l, line in enumerate(f.readlines()):
            if l != 0:
                if index == 0:
                    (srcip, destip, sport, dport, proto, pkts, size, first, last,
                     duration) = [convert_value(x) for x in line.split("\t")]
                else:
                    (srcip, destip, sport, dport, proto, tgh, avg, max_size,
                    total_size, wire_size, pkts, empty_pkts, first, last,
                    interarrival, duration) = [convert_value(x) for x in line.split("\t")]

                    
                    pkts = pkts - empty_pkts
                    size = wire_size - (empty_pkts * 60)

                flowkey = (sport, dport, proto)
                flows.add((srcip, destip, sport, dport, proto))
                ip_addresses.add(srcip)
                ip_addresses.add(destip)
                try:
                    flow_thg = (size/1000.0)/(duration/1000.0)
                except ZeroDivisionError:
                    flow_thg = 0

                total_size_array.append(size)
                pkts_array.append(pkts)
                payload_thg_avg.append(flow_thg)

                stats = FlowStats(size, pkts, flow_thg, duration)

                if flowkey not in flows_difference:
                    flows_difference[flowkey] = [stats]
                else:
                    flows_difference[flowkey].append(stats)

                if proto == TCP:
                    all_size_tcp.append(size)
                    all_dur_tcp.append(duration)

                np_size_array = np.array(total_size_array)
                np_pkts_array = np.array(pkts_array)
                np_thg_array = np.array(payload_thg_avg)

        sizes.append(all_size_tcp)
        durations.append(all_size_tcp)
        nbr_packets.append(pkts_array)
        thg_averages.append(payload_thg_avg)

    compare_cdf(sizes[0], sizes[1], "size", "sim", "real", "Bytes",
                "P(X<=x)")
    compare_cdf(durations[0], durations[1], "duration", "sim", "real",
                "Duration (ms)", "P(X<=x)")
    compare_cdf(nbr_packets[0], nbr_packets[1], "nbr packets w/o ACK",
                "sim", "real", "#Pkts", "P(X<=x)") 
    compare_cdf(thg_averages[0], thg_averages[1], "throughput w/ hdr",
                "sim", "real", "Throughput (kB/s)", "P(X<=x)")

def main(gfile, rfile, directory):

    sizes = []
    durations = []
    nbr_total_packets = []
    nbr_packets = []
    total_thg_averages = []
    thg_averages = []

    flows_difference = {}

    FlowStats = namedtuple('FlowStats', ['size', 'pkts', 'thg', 'dur'])
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
        total_pkt_array = []
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

        payload_thg_avg = []
        total_thg_avg = []

        flows = set() 

        ip_addresses = set()

        hmis = set()

        gateways = set()
        rpc_size = []
        rpc_pkts = []


        size_repartition = {}
        pkts_repartition = {}

        hmi_mtu = 0

        for l,line in enumerate(f.readlines()):
            if l != 0:
                (srcip, destip, sport, dport, proto, tgh, avg, max_size,
                 total_size, wire_size, pkts, empty_pkts, first, last,
                 interarrival, duration) = [convert_value(x) for x in line.split("\t")]

                flowkey = (sport, dport, proto)
                flows.add((srcip, destip, sport, dport, proto))
                ip_addresses.add(srcip)
                ip_addresses.add(destip)

                payload_pkt = pkts - empty_pkts

                try:

                    flow_thg = (total_size/1000.0)/((duration)/1000.0)
                    total_flow_thg = (wire_size/1000.0)/(duration/1000.0)
                except ZeroDivisionError:
                    flow_thg = 0
                    total_flow_thg = 0
                    print "one failed flow"

                if sport in size_repartition:
                    size_repartition[sport] += total_size
                else:
                    size_repartition[sport] = total_size

                if sport in pkts_repartition:
                    pkts_repartition[sport] += payload_pkt
                else:
                    pkts_repartition[sport] = payload_pkt

                total_size_array.append(total_size)
                total_pkt_array.append(pkts)
                # Only packet containing payload
                pkts_array.append(payload_pkt)
                payload_thg_avg.append(flow_thg)
                total_thg_avg.append(total_flow_thg)

                stats = FlowStats(total_size,
                                  payload_pkt,
                                  flow_thg,
                                  duration)

                if flowkey not in flows_difference:
                    flows_difference[flowkey] = [stats]
                else:
                    flows_difference[flowkey].append(stats)

                if proto == TCP:
                    all_inter_tcp.append(interarrival)
                    all_size_tcp.append(total_size)
                    all_dur_tcp.append(duration)

                    if sport in hmi_port or dport in hmi_port:
                        hmi_to_mtu_size.append(total_size)
                        hmi_to_mtu_pkt.append(payload_pkt)

                        hmi_mtu += total_size

                        # Port open on the mtu
                        if sport in hmi_port:
                            hmis.add(srcip)
                        else:
                            hmis.add(destip)


                    if sport in gateways_port or dport in gateways_port:
                        mtu_to_gateway_size.append(total_size)
                        mtu_to_gateway_pkt.append(payload_pkt)

                        if sport in gateways_port:
                            gateways.add(srcip)
                        else:
                            gateways.add(destip)

                    if sport in web_port or dport in web_port:
                        web_size.append(total_size)
                        web_pkt.append(payload_pkt)

                    if sport in rpc_port or dport in rpc_port: 
                        hmi_to_mtu_size.append(total_size)
                        hmi_to_mtu_pkt.append(payload_pkt)

                elif proto == UDP:
                    all_inter_udp.append(interarrival)
                    all_size_udp.append(total_size)
                    all_dur_udp.append(duration)

                    if sport in web_port or dport in web_port:
                        web_size.append(total_size)
                        web_pkt.append(payload_pkt)

                    if sport in netbios_port or dport in netbios_port:
                        netbios_size.append(total_size)
                        netbios_pkts.append(payload_pkt)

        total_size_rep = sum(size_repartition.values())
        for k in size_repartition:
            size_repartition[k] = size_repartition[k]/float(total_size_rep)

        sorted_size = sorted(size_repartition.items(), key=operator.itemgetter(1))

        np_size_array = np.array(total_size_array)
        np_total_pkts_array = np.array(total_pkt_array)
        np_pkts_array = np.array(pkts_array)
        np_thg_array = np.array(payload_thg_avg)
        np_total_thg_array = np.array(total_thg_avg)

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
            f.write("HMI size:{} ({}%)\n".format(np.sum(np_hmi_size),
                                                 100*(np.sum(np_hmi_size)/float(tmp_total))))
            f.write("MTU size:{} ({}%)\n".format(np.sum(np_mtu_size),
                                                 100*(np.sum(np_mtu_size)/float(tmp_total))))
            f.write("Web size:{} ({}%)\n".format(np.sum(np_web_size),
                                                 100*(np.sum(np_web_size)/float(tmp_total))))
            f.write("Netbios size:{} ({}%)\n".format(np.sum(np_netbios_size),
                                                     100*(np.sum(np_netbios_size)/float(tmp_total))))
            f.write("min pkt:{}\n".format(np.min(np_pkts_array)))
            f.write("avg pkt:{}\n".format(np.average(np_pkts_array)))
            f.write("max pkt:{}\n".format(np.max(np_pkts_array)))

            tmp_total = np.sum(np_pkts_array)
            f.write("Total pkt: {}\n".format(tmp_total))
            f.write("HMI pkt:{} ({}%)\n".format(np.sum(np_hmi_pkt),
                                                100*(np.sum(np_hmi_pkt)/float(tmp_total))))
            f.write("MTU pkt:{} ({}%)\n".format(np.sum(np_mtu_pkt),
                                                100*(np.sum(np_mtu_pkt)/float(tmp_total))))
            f.write("Web pkt:{} ({}%)\n".format(np.sum(np_web_pkt),
                                                100*(np.sum(np_web_pkt)/float(tmp_total))))
            f.write("Netbios pkt:{} ({}%)\n".format(np.sum(np_netbios_pkt),
                                                    100*(np.sum(np_netbios_pkt)/float(tmp_total))))
            f.write("-----------\n\n")

        sizes.append(all_size_tcp + all_size_udp)
        durations.append(all_dur_tcp + all_dur_udp)
        nbr_packets.append(pkts_array)
        nbr_total_packets.append(total_pkt_array)
        thg_averages.append(payload_thg_avg)
        total_thg_averages.append(total_thg_avg)
        f.close()

    #display_flowstat(flows_difference)

    compare_cdf(sizes[0], sizes[1], "size", "gen", "real", "Bytes", "P(X<=x)")
    compare_cdf(durations[0], durations[1], "duration", "gen", "real",
                "Duration (ms)", "P(X<=x)")
    compare_cdf(nbr_packets[0], nbr_packets[1], "nbr packets w/o ACK", "gen",
                "real", "#Pkts", "P(X<=x)")

    compare_cdf(nbr_total_packets[0], nbr_total_packets[1], "nbr packets w/ ACK",
                "gen", "real", "#Pkts", "P(X<=x)")
    compare_cdf(thg_averages[0], thg_averages[1], "throughput", "gen", "real",
                "Throughput (kB/s)", "P(X<=x)")
    compare_cdf(total_thg_averages[0], total_thg_averages[1], "throughput w/ hdr",
                "gen", "real", "Throughput (kB/s)", "P(X<=x)")

def read(_type, readsize, f, index):
    return index+readsize, struct.unpack(_type, f.read(readsize))[0]

def plot_time_series(ts):
    hours = max([len(x) for x in ts])
    y = np.array([x for x in xrange(hours)])

    for t in ts:
        x = np.array(t)
        res = np.zeros(y.shape)
        res[:x.shape[0]] = x
        plt.plot(y, res)
    plt.show()

def compare_timeseries(line_number, title, xlabel, *argv):

    stats = []

    for filename in argv:
        f = open(filename, "r")
        for l, line in enumerate(f.readlines()):
            if l == line_number:
                timeseries = np.array([int(x) for x in line.split("\t")])
                stats.append(timeseries)

    plot_time_series(stats)

def compare_flow_stats(line_number, title, xlabel, *argv):

    stats = []

    for filename in argv:
        f = open(filename, "r")
        for l, line in enumerate(f.readlines()):
            if l == line_number:
                vals = line.split("\t")
                for v in vals:
                    try:
                        float(v)
                    except ValueError:
                        print v
                        break
                list_stat = np.array([float(x) for x in line.split("\t")])
                stats.append(list_stat)
                print "--------------------------------"
                print "Max: %s \n " % np.max(list_stat)
                print "Min: %s \n " % np.min(list_stat)
                print "Avg: %s \n " % np.average(list_stat)
                print "Std: %s \n " % np.std(list_stat)
                print "--------------------------------"
    compare_cdf(stats[0], stats[1], title, "gen", "real", xlabel,
                "P(X<=x)")

if __name__ == "__main__":
    '''
    if not args.sim:
        main(args.gfile, args.rfile, args.directory)
    else:
        compare_with_simulation(args.gfile, args.rfile)
    '''
    print "Inter-packet time 1. Gen 2. Real"
    compare_flow_stats(3, "IPT CDF", "Inter-Packet Time (ms)", args.gipt, args.ript)
    print "Packet size 1. Gen 2. Real"
    compare_flow_stats(4, "PS CDF", "Packet Size (B)", args.gipt, args.ript)
    print "Inter-packet time 1. Gen 2. Real, other direction"
    compare_flow_stats(8, "IPT CDF (Rev)", "Inter-Packet Time (ms)", args.gipt, args.ript)
    print "Packet size 1. Gen 2. Real other direction"
    compare_flow_stats(9, "PS CDF (Rev)", "Packet Size (B)", args.gipt, args.ript)
    compare_timeseries(1, "Nbr Pkt", "Nbr Pkt", args.gipt, args.ript)
    compare_timeseries(2, "Size", "Size Pkt", args.gipt, args.ript)
    compare_timeseries(6, "Nbr Pkt", "Nbr Pkt", args.gipt, args.ript)
    compare_timeseries(7, "Nbr Pkt", "Nbr Pkt", args.gipt, args.ript)
