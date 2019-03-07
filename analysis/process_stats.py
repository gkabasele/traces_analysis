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
    parser.add_argument("-f", type=str, dest="filename", action="store", help="input file containing the stats")
    parser.add_argument("-t", type=str, dest="timeseries", action="store", help="input file containing the timeseries")
    parser.add_argument("-c", type=str, dest="connections", action="store", help="input file containing information from connections")
    parser.add_argument("-d", type=str, dest="directory", action="store", help="directory where to output the plots")
    parser.add_argument("-s", type=str, dest="sizefile", action="store", help="input file containinng list of packet size for a flow")
    args = parser.parse_args()


hmi_port = ["50000", "135", "445"]
gateways_port = ["2499"]
web_port = ["80", "889", "443", "53"] 
netbios_port = ["137", "138"]
snmp_port = ["161", "162"]
rpc_port = ["50540", "54540", "55844", "49885", "58658", "56427", "62868", "59303", "53566"]  


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


## From MJ
# add point on y axis
def _one_dot_by_instance(bin_edges, cdf, nbr_instances):
    new_bin_edges = []
    new_cdf = []
    i = 0
    for l in np.linspace(0, 1, num=nbr_instances + 1):
        if i == len(cdf):
            break
        new_bin_edges.append(bin_edges[i])
        new_cdf.append(l)
        if math.fabs(cdf[i] - l) <= 10e-6:
            i += 1
    return new_bin_edges, new_cdf

def _histogram_data(bounded_data):
    counts = []
    bin_edges = []
    bounded_data = sorted(bounded_data)
    for i in range(len(bounded_data)):
        if len(bin_edges) != 0 and bin_edges[-1] == bounded_data[i]:
            counts[-1] += 1
        else:
            counts.append(1)
            bin_edges.append(bounded_data[i])
    return counts, bin_edges


def _cdf_data(cdf_values):
    data = sorted(cdf_values)
    num_bins = 10**5

    # Count and filter math.inf
    bounded_data = []
    for value in data:
        if not math.isinf(value):
            bounded_data.append(value)

    counts, bin_edges = _histogram_data(bounded_data)
    cdf = np.cumsum(counts)
    cdf = (cdf / cdf[-1]) * (len(bounded_data) / len(data))  # Unsolved instances hurts the cdf 
    bin_edges = list(bin_edges)
    bin_edges.insert(0, 0)
    cdf = list(cdf)
    cdf.insert(0, 0)
    return bin_edges, cdf


def plot_from_data(filename, values, xlabel, title, div=1):
    vals = divide_by(values, div)
    bins_edges, cdf = _cdf_data(vals)
    plt.plot(bins_edges, cdf)
    plt.xlabel(xlabel)
    plt.title(title)
    plt.savefig(filename)
    plt.close()

## end##


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

                if srcip == "252.103.119.36" or destip == "252.103.119.36":
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
    with open(stat_file, "w") as f:
        f.write("++Summary++\n")
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

    plot_cdf(directory + "/" + "flow_size_cdf.png", [all_size_tcp + all_size_udp], ["Flow size"], [1000], "Size (kB) (log)", "CDF","CDF of flow size", 10**-2, 6*(10**5))
    #FIXME Wrong packet number cdf
    plot_cdf(directory + "/" + "flow_nbr_pkt_cdf.png", [all_size_tcp + all_dur_udp], ["Flow Packet Nbr"], [1], "Nbr Pkts (log) ", "CDF", "CDF of packet number", 10**1, 10**9)

    plot_cdf(directory + "/" + "flow_duration_cdf.png",[all_dur_tcp + all_dur_udp], ["Flow duration"], [3600000],"Duration (Hour) (log)", "CDF","CDF of duration",10**-6, 3*(10**2))



    ##plot_from_data(directory +"/" + "flow_duration_cdf_v2.png", all_dur_tcp + all_dur_udp, "Duration (Hour)", "CDF of duration", 3600000) 
    ##plot_from_data(directory + "/" + "flow_size_cdf_v2.png", all_size_tcp + all_size_udp, "Size (kB)", "CDF of flow size", 1000)

    ## Timerseries analysis
    flow_labels = []
    list_pkts = []
    list_size = []
    list_packet_size = []

    bna_inter = []

    for l, line in enumerate(ts.readlines()):
        if l % 5 == 0:
            (flow, proto) = line.split()
            flow_labels.append(flow)
        elif (l + 4) % 5 == 0:
            nbr_pkt = line.split("\t")
            list_pkts.append([int(x) for x in nbr_pkt])
        elif (l + 3) % 5 == 0:
            size = line.split("\t")
            list_size.append([int(x) for x in size])
        elif (l + 2) % 5 == 0:
            bna_inter = [ int(x) for x in line.split("\t")]
        elif (l + 1) % 5 == 0:
            list_packet_size = [ int(x) for x in line.split("\t")]

    sorted_bna_inter = sorted(bna_inter)

    plot_hourly(directory + "/" + "nbr_pkt.png", list_pkts, ["Gateway->Server", "Server->Gateway"], "Hour", "#PKTS", "Nbr Pkts per hour")

    plot_hourly(directory + "/" + "size.png", list_size, ["Gateway->Server", "Server->Gateway"], "Hour", "kB", "Kilobytes per hour", 1000)

    res = np.array(sorted_bna_inter)
    bins = None

    ## New connections by hour
    label = []
    tcp_new_conn = []
    udp_new_conn = []
    bna_new_conn = []
    hmi_new_conn = []

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
        elif l == 7:
            hmi_new_conn = [int(x) for x in line.split("\t")]

    hvac = [ x+y for x, y in zip(bna_new_conn, hmi_new_conn)]

    plot_hourly(directory + "/" + "new_flow.png", [tcp_new_conn, udp_new_conn, hvac], ["TCP", "UDP", "HVAC"], "Hour", "#Flow", "Flow discovery per hour")

    f.close()
    ts.close()
    conn.close()


def read(_type, readsize, f, index):
    return index+readsize, struct.unpack(_type, f.read(readsize))[0]
    
def packet_size_dist(filename, directory):
    sizes = []
    index = 0
    with open(filename, "rb") as f:
        filesize = os.path.getsize(filename)
        while index < filesize:
            index, s = read('H', 2, f, index)
            sizes.append(s)

    pkts_size = np.array(sizes)

    C = Counter(pkts_size)
    total = float(sum(C.values()))
    for key in C:
        C[key] /=total
    plt.bar(sorted(C.keys()), C.values(), width=4)
    plt.xlabel("Size (B)")
    plt.title("PDF of packet size")
    plt.show()

def flow_by_hour(filename, directory, ip_address):
    start_hour = 0
    end_hour =0 
    one_hour = datetime.timedelta(hours=1)

    in_hourly = []
    out_hourly = []

    in_size_hour = 0

    out_size_hour = 0

    tcp_hourly = []
    udp_hourly = []
    bna_hourly = []

    tcp_hour = 0
    udp_hour = 0
    bna_hour = 0

    flows = set()

    with open(filename, "r") as f:
        for l,line in enumerate(f.readlines()):
            if l != 0:
                (srcip, destip, sport, dport, proto, tgh, avg, max_size, 
                        total_size, wire_size, pkts, first, last, interarrival, duration) = line.split("\t")

                flow = (srcip, destip, sport, dport, proto)
                cur_time =  datetime.datetime.strptime(first, "%Y-%m-%d %H:%M:%S.%f")

                if start_hour ==  0:
                    start_hour = cur_time.replace(microsecond=0)
                    end_hour = start_hour + one_hour 

                    
                elif cur_time >= end_hour:
                    tcp_hourly.append(tcp_hour)
                    bna_hourly.append(udp_hour)
                    udp_hourly.append(bna_hour)

                    start_hour = start_hour + one_hour
                    end_hour = start_hour + one_hour

                    tcp_hour = 0
                    udp_hour = 0
                    bna_hour = 0

                if flow not in flows:

                    flows.add(flow)

                    if int(proto) == TCP:
                        tcp_hour += 1

                        if sport in gateways_port or dport in gateways_port:
                            bna_hour += 1
                        
                        if sport in hmi_port or dport in hmi_port:
                             bna_hour += 1
                    if int(proto) == UDP:
                        
                        udp_hour += 1
                    
    tcp_hourly.append(tcp_hour)
    udp_hourly.append(udp_hour)
    bna_hourly.append(bna_hour)

    print len(tcp_hourly)
    plot_hourly(directory + "/" + "hourly_flow_discovery.png", [tcp_hourly, udp_hourly, bna_hourly], ["TCP", "UDP", "HVAC"], "#Flow", "Hour", "Flow discovery per hour")

if __name__=="__main__":
    main(args.filename, args.timeseries, args.connections, args.directory)
    #packet_size_dist(args.sizefile, args.directory)
    #flow_by_hour(args.filename, args.directory, "50.39.135.125")
    
