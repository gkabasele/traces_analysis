import sys
import subprocess
import argparse
from datetime import datetime
import time
import dateutil.parser

import threading
import os


parser = argparse.ArgumentParser()
parser.add_argument("-f1", type=str, dest="file1", action="store")
parser.add_argument("-f2", type=str, dest="file2", action="store")
parser.add_argument("-f3", type=str, dest="file3", action="store")
parser.add_argument("-c", type=str, dest="count", action="store")

args = parser.parse_args()


class State(object):

    def __init__(self, history, begin, end, offset, dirname, fname):
        self.history = history
        self.begin = begin
        self.end = end
        self.offset = offset
        self.dirname = dirname
        self.fname = fname

def conv_time(date):

    return dateutil.parser.parse(date)

def parse_line(line, state):

    (number, phys_time, ident, seq, type, snd, rcv) = line.split("|")
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
            start_shifting(state)
            state.end = state.begin
        else:
            print "Error, unknown identifier"

def compute_offset(seq):

    # if no reply was received for a request
    try:
        time_diff = seq['rcv_remote'] - seq['snd_local'] # in milliseconds
        net_delay = seq['phys_rcv_local'] - seq['phys_snd_local'] # return timedelta (days, seconds, microsecond)
        return time_diff - int(net_delay.total_seconds() * 1000)/float(2)
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

def worker(fname, result):

    # Keep information about time event of the icmp timestamps requests
    history = {}
    
    # Where to begin and where to end the timestamp shifting : begin >= end
    begin = 0
    end = 0
    
    # last computed offset
    offset = 0
    
    # A
    dirname = []

    state = State(history, begin, end, offset, dirname, fname)
    
    cmd = ["tshark", "-r", fname, "-Y", "icmp", "-u","s", "-T", "fields", "-E", "separator=|", "-e", "frame.number" ,"-e", "frame.time", "-e", "icmp.ident", "-e", "icmp.seq", "-e", "icmp.type" ,"-e", "icmp.originate_timestamp", "-e", "icmp.receive_timestamp"]
    tshark = subprocess.check_output(cmd)
    
    line = tshark.split('\n')







    
    for info in line[:-1]:
        parse_line(info, state)
        if len(state.dirname) > 1:
            res = merge_trace(state)
            state.dirname = [res]
    
    filename = "{}_{}-last.pcap".format(fname[:-5], state.end)
    cmd = ["editcap", fname, filename, "0-{}".format(state.end)]
    res = subprocess.check_output(cmd)
    
    new_filename = filename + "_adjusted.pcap"
    cmd = ["editcap", "-t", str(offset/1000), filename, new_filename]
    res = subprocess.check_output(cmd)
    state.dirname.append(new_filename)
    
    cmd = ["mergecap", "-w", "{}_adjusted.pcap".format(fname[:-5])] + state.dirname
    subprocess.check_output(cmd)

    result.append("{}_adjusted.pcap".format(fname[:-5]))
    
    remove_file(filename)
    remove_directory(state.dirname)

# Split the file for each thread
split_name = "splitted.pcap"

cmd = ["editcap", "-c", args.count, args.file1, split_name]
subprocess.check_output(cmd)

threads = []

files = []

resFiles = []

for fname in os.listdir(os.getcwd()): 
    if fname.startswith("splitted"):
        #start worker
        files.append(fname)
        t = threading.Thread(target=worker, args=(fname, resFiles))
        threads.append(t)
        t.start()

for t in threads:
    t.join()

cmd = ["rm"] + files
subprocess.check_output(cmd)
# Merge all the resulting file

if len(resFiles) > 1:

    cmd = ["mergecap", "-w", "{}_adjusted.pcap".format(args.file1[:-5])] + resFiles
    subprocess.check_output(cmd)

if len(resFiles) >= 1:
    remove_directory(resFiles)
