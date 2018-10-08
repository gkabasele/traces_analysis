#!/usr/bin/env python
import matplotlib.pyplot as plt
import matplotlib as mpl
import os
import sys
import argparse
from datetime import datetime, timedelta, time, date

parser = argparse.ArgumentParser()
parser.add_argument("-f", type=str, dest="filename", action="store", help="input file containing the stats")
args = parser.parse_args()


def plot_hourly(x, y, ticks ,labels ,xlabel, ylabel, title, div=1):
    plt.subplot(111)
    plt.xlabel(xlabel)
    plt.ylabel(ylabel)
    plt.title(title)
    plt.plot(x,y)
    plt.xticks(ticks, labels, rotation='vertical')
    plt.show()

if __name__=="__main__":
    f = open(args.filename, "r")

    list_pkts = []
    list_size = []
    bna_inter = []

    for  l, line in enumerate(f.readlines()):
        if l % 4 == 0:
            (flow, proto) = line.split()
        elif (l + 3) % 4 == 0:
            nbr_pkt = line.split("\t")
            list_pkts.append([ int(x) for x in nbr_pkt])
        elif (l + 2) % 4 == 0:
            size = line.split("\t")
            list_size.append([ int(x) for x in size])
        elif (l + 1) % 4 == 0:
            bna_inter = [ int(x) for x in line.split("\t")] 

    sorted_bna_inter = sorted(bna_inter)

    t = time(14, 3, 0) 
    times = []
    for x in range (len(list_size[0])):  
        val = (datetime.combine(date(1,1,1), t) + timedelta(hours=x)).time()   
        times.append(val) 
    ticks = [x for x in range (0, len(list_size[0])) if x % 8 == 0]
    labels = [d for i, d in enumerate(times) if i % 8 == 0]

    plot_hourly(range(1, len(list_size[0]) + 1), list_size[0], ticks, labels,"hour", "size", "title")

    f.close()


