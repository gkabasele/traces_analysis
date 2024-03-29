import sys
import subprocess
import argparse
from datetime import datetime
import time
import dateutil.parser

import threading
import os
import numpy as np


parser = argparse.ArgumentParser()
parser.add_argument("-f1", type=str, dest="file1", action="store", help="input file containing the trace from both capture point")
parser.add_argument("-f2", type=str, dest="file2", action="store", help="input file containing the trace from only one of the capture point")
parser.add_argument("-o", type=str, dest="output", action="store", help="output file containing for icmp exchange, its position, sequence number and computed offset")
parser.add_argument("-d", dest="debug", action="store_true")

args = parser.parse_args()


class State(object):

    def __init__(self, history, begin, end, offset, dirname, fname):
        self.history = history
        self.begin = begin
        self.end = end
        self.offset = offset
        self.dirname = dirname
        self.fname = fname

class ICMPExchange(object):

    def __init__(self):

        self.phys_req_a = None
        self.phys_res_a = None
        self.phys_req_b = None
        self.phys_res_b = None

    def compute_network_delay(self):

        rtt_a  = (self.phys_res_a - self.phys_req_a).total_seconds() * 1000
        return rtt_a/float(2)
        #rtt_b = (self.phys_res_b - self.phys_req_b).total_seconds() * 1000 # time taken to generate the packet
        #return (rtt_a - rtt_b) / float(2)

    def compute_offset(self):

        time_diff = (self.phys_req_b - self.phys_req_a).total_seconds() * 1000
        offset =  time_diff - self.compute_network_delay()
        return offset
    
    def is_complete(self):

        return (self.phys_req_a and self.phys_req_b 
                and self.phys_res_a and self.phys_res_b)

    def __str__(self):
        return ( "Phys_req_a: {} \n".format(self.phys_req_a) +
                 "Phys_req_b: {} \n".format(self.phys_req_b) +
                 "Phys_res_a: {} \n".format(self.phys_res_a) +
                 "Phys_res_b: {} \n".format(self.phys_res_b) )

def conv_time(date):

    return dateutil.parser.parse(date)

def parse_merge(line, state, f, numbers):
    try:
        (number, phys_time, ident, seq, type, ttl) = line.split("|")
    except ValueError as err:
        print("Input causing the error: {}".format(line))
        print("{}".format(err.message))
        return

    if type == "13":
        if ident not in state.history:
            exchange = ICMPExchange()
            if ttl == "64":
                exchange.phys_req_a = conv_time(phys_time)
                state.history[ident] = { seq : exchange }
            elif ttl == "61":
                exchange.phys_req_b = conv_time(phys_time)
                state.history[ident] = { seq : exchange }
        else:
            if seq in state.history[ident]:
                if ttl == "64":
                    state.history[ident][seq].phys_req_a = conv_time(phys_time)
                elif ttl == "61":
                    state.history[ident][seq].phys_req_b = conv_time(phys_time)
            else:
                exchange = ICMPExchange()
                if ttl == "64":
                    exchange.phys_req_a = conv_time(phys_time)
                    state.history[ident][seq] = exchange
                elif ttl == "61":
                    exchange.phys_req_b = conv_time(phys_time)
                    state.history[ident][seq] = exchange 
    elif type == "14":
        if ident in state.history:
            if ttl == "61":
                state.history[ident][seq].phys_res_a = conv_time(phys_time)
            elif ttl == "64":
                state.history[ident][seq].phys_res_b = conv_time(phys_time)
            if state.history[ident][seq].is_complete():
                offset = state.history[ident][seq].compute_offset()
                f.write("{},{},{}\n".format(numbers[seq],seq, offset))
                if args.debug:
                    print state.history[ident][seq]
                    f.close()
                    exit()


        else:
            raise ValueError("Unknown icmp identifier: {}".format(ident))


def parse_line(line, state, f):

    (number, phys_time, ident, seq, type, snd, rcv, ttl) = line.split("|")
    if type == "13":
        if ident in state.history:
            state.history[ident][seq] = {"phys_snd_local" : conv_time(phys_time), "snd_local" : int(snd)}
        else:
            state.history[ident] = { seq : {"phys_snd_local" : conv_time(phys_time), "snd_local" : int(snd)}}
    elif type == "14":
        if ident in state.history:
            state.history[ident][seq]["phys_rcv_local"] = conv_time(phys_time)
            state.history[ident][seq]["rcv_remote"] = int(rcv)
            state.offset = compute_offset(state.history[ident][seq])
            state.begin = number
            f.write("{},{},{}\n".format(state.end, state.begin, state.offset))
            state.end = state.begin
        else:
            raise ValueError("Unknown icmp identifier: {}".format(ident))


def compute_offset(seq):

    # if no reply was received for a request
    try:
        time_diff = seq['rcv_remote'] - seq['snd_local'] # in milliseconds
        net_delay = seq['phys_rcv_local'] - seq['phys_snd_local'] # return timedelta (days, seconds, microsecond)
        return time_diff - int((net_delay.total_seconds() * 1000))/float(2)
    except KeyError:
        return 0

def start_shifting(state):

    filename = "{}_{}-{}".format(state.fname[:-5], state.end, state.begin)
    cmd = ["editcap", "-r", state.fname, filename, "{}-{}".format(state.end, state.begin)]
    res = subprocess.check_output(cmd)
    
    new_filename = filename + "_adjusted.pcap"
    cmd = ["editcap", "-t", str(state.offset/1000), filename, new_filename]
    res = subprocess.check_output(cmd)
    state.dirname.append(new_filename)
    remove_file(filename)

def merge_trace(state):

    filename = "{}_tmp_0-{}.pcap".format(state.fname[:-5], state.begin)
    cmd = ["mergecap", "-w", filename] + state.dirname
    subprocess.check_output(cmd)
    remove_directory(state.dirname)
    return filename
    
def remove_file(filename):
    
    cmd = ["rm", filename]
    subprocess.check_output(cmd)

def remove_directory(dirname):

    cmd = ["rm"] + dirname
    subprocess.check_output(cmd)


def add_frame_number(numbers, line):
    if "invalid" not in line:
        (number, phys_time, ident, seq, type, ttl) = line.split("|")
    
        if seq not in numbers:
            numbers[seq] = number

def worker(fboth, fshut, output):

    # Keep information about time event of the icmp timestamps requests
    history = {}
    
    # Where to begin and where to end the timestamp shifting : begin >= end
    begin = 0
    end = 0
    
    # last computed offset
    offset = 0
    
    # A
    dirname = []

    pktNbr = 0

    state = State(history, begin, end, offset, dirname, fboth)

    f = open("{}".format(output), "w")

    cmd = ["tshark", "-r", fshut, "-n", "-Y", "icmp", "-u","s", "-T", "fields", "-E", "separator=|", "-e", "frame.number" ,"-e", "frame.time", "-e", "icmp.ident", "-e", "icmp.seq", "-e", "icmp.type", "-e","ip.ttl"]
    res = subprocess.check_output(cmd)
    icmp_shut = res.split('\n')

    numbers = {}

    for info in icmp_shut[:-1]:
        add_frame_number(numbers, info)
    
    cmd = ["tshark", "-r", fboth, "-n", "-Y", "icmp", "-u","s", "-T", "fields", "-E", "separator=|", "-e", "frame.number" ,"-e", "frame.time", "-e", "icmp.ident", "-e", "icmp.seq", "-e", "icmp.type", "-e","ip.ttl"]
    tshark = subprocess.check_output(cmd)
    icmp_both_shut = tshark.split('\n')


    # Last line is empty
    for info in icmp_both_shut[:-1]:
        parse_merge(info, state, f, numbers)

    f.close()
'''    
    cmd = ["capinfos", fname]
    capinfos = subprocess.check_output(cmd)
    infos = capinfos.split('\n')

    for info in infos:
        if "Number of packets = " in info:
            print info
            pktNbr = info.split('=')[1] 
            print pktNbr

    
    for info in line[:-1]:
        parse_line(info, state, f)

    f.write("{},{},{}\n".format(state.begin, pktNbr, state.offset))

    f.close()
    
'''

worker(args.file1, args.file2, args.output)
