import sys
import subprocess
import argparse
from datetime import datetime
import time
import dateutil.parser


parser = argparse.ArgumentParser()
parser.add_argument("-f1", type=str, dest="file1", action="store")
parser.add_argument("-f2", type=str, dest="file2", action="store")
parser.add_argument("-f3", type=str, dest="file3", action="store")

args = parser.parse_args()

# Keep information about time event of the icmp timestamps requests
history = {}

# Where to begin and where to end the timestamp shifting : begin >= end
begin = 0
end = 0

# last computed offset
offset = 0

# A
dirname = []


def conv_time(date):
    return dateutil.parser.parse(date)

def parse_line(line):
    (number, phys_time, ident, seq, type, snd, rcv) = line.split("|")
    if type == "13":
        if ident in history:
            history[ident][seq] = {"phys_snd_local" : conv_time(phys_time), "snd_local" : int(snd)}
        else:
            history[ident] = { seq : {"phys_snd_local" : conv_time(phys_time), "snd_local" : int(snd)}}
    elif type == "14":
        if ident in history:
            history[ident][seq]["phys_rcv_local"] = conv_time(phys_time)
            history[ident][seq]["rcv_remote"] = int(rcv)
            global offset
            global begin
            global end
            offset = compute_offset(history[ident][seq])
            begin = number
            start_shifting(offset, begin, end)
            end = begin
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


def start_shifting(offset, begin, end):
    filename = "{}_{}-{}".format(args.file1[:-5], end, begin)
    cmd = ["editcap", "-r", args.file1, filename, "{}-{}".format(end, begin)]
    res = subprocess.check_output(cmd)
    
    new_filename = filename + "_adjusted.pcap"
    cmd = ["editcap", "-t", str(offset/1000), filename, new_filename]
    res = subprocess.check_output(cmd)
    dirname.append(new_filename)
    remove_file(filename)

def merge_trace(traces, begin):
    filename = "{}_tmp_0-{}.pcap".format(args.file1[:-5], begin)
    cmd = ["mergecap", "-w", filename] + traces
    subprocess.check_output(cmd)
    remove_directory(dirname)
    return filename
    
def remove_file(filename):
    cmd = ["rm", filename]
    subprocess.check_output(cmd)

def remove_directory(dirname):
    cmd = ["rm"] + dirname
    subprocess.check_output(cmd)


cmd = ["tshark", "-r", args.file1, "-Y", "icmp", "-u","s", "-T", "fields", "-E", "separator=|", "-e", "frame.number" ,"-e", "frame.time", "-e", "icmp.ident", "-e", "icmp.seq", "-e", "icmp.type" ,"-e", "icmp.originate_timestamp", "-e", "icmp.receive_timestamp"]
tshark = subprocess.check_output(cmd)

line = tshark.split('\n')

for info in line[:-1]:
    parse_line(info)
    if len(dirname) > 1:
        res = merge_trace(dirname, begin)
        dirname = [res]

    
filename = "{}_{}-last.pcap".format(args.file1[:-5], end)
cmd = ["editcap", args.file1, filename, "0-{}".format(end)]
res = subprocess.check_output(cmd)

new_filename = filename + "_adjusted.pcap"
cmd = ["editcap", "-t", str(offset/1000), filename, new_filename]
res = subprocess.check_output(cmd)
dirname.append(new_filename)

print dirname

cmd = ["mergecap", "-w", "{}_adjusted.pcap".format(args.file1[:-5])] + dirname
subprocess.check_output(cmd)

remove_file(filename)
remove_directory(dirname)

#merge all created file

#all_offset = []
#for ident in history:
#    for seq in history[ident]:
#        all_offset.append(compute_offset(history[ident][seq]))
#
#offset = sum(all_offset)/float(len(all_offset))
#print "The timestamp of this trace, is of by {} milliseconds".format(offset)
    
