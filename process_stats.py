#!/usr/bin/env python

import matplotlib.pyplot as plt
import matplotlib as mpl
import numpy as np
import os 
import sys
import argparse
import functools
from numpy import cumsum


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
parser.add_argument("-f", type=str, dest="filename", action="store", help="input file containing the file")
args = parser.parse_args()



def main(filename):

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
    all_inter = []
    all_size = []

    x_value = sorted(dist.keys())
    
    for l,line in enumerate(f.readlines()):
        if l != 0:
            (srcip, destip, sport, dport, proto, tgh, avg, max_size, 
                    total_size, wire_size, pkts, first, last, interarrival) = line.split("\t")
            all_inter.append(int(interarrival))
            all_size.append(int(total_size))
            for i in range(len(x_value)- 1):
                lower = x_value[i]
                upper = x_value[i+1]
                if int(interarrival) in range(lower, upper):
                    dist[lower] += 1
    print dist
    y_value = [ dist[v] for v in x_value ] 


    # Inter arrival
    sorted_arrival = np.sort(all_inter)
    p = 1. * np.arange(len(all_inter))/(len(all_inter) - 1)
    plt.plot(sorted_arrival, p)
    plt.show()


    # Inter total bytes
    sorted_size = np.sort(all_size)
    q = 1. * np.arange(len(all_size))/(len(all_size) - 1) 
    plt.plot(sorted_size, q)
    plt.show()

if __name__=="__main__":
    main(args.filename)
