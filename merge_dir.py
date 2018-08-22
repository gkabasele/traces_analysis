import sys
import subprocess
import argparse
import os
import itertools
from difflib import SequenceMatcher

parser = argparse.ArgumentParser()
parser.add_argument("-s1", type=str, dest="shut1", action="store", help="Directory containing the trace from shuttle 1")
parser.add_argument("-s2", type=str, dest="shut2", action="store", help="Directory containing the trace from shuttle 2")
parser.add_argument("-m", type=str, dest="merge_dir", action="store", help="Directory where merge will be outputed")
parser.add_argument("-a", type=str, dest="adjusted_dir", action="store", help="Directory where adjusted will be outputed")
parser.add_argument("-ma", type=str, dest="merge_adjusted_dir", action="store", help="Directory where merge adjusted will be outputed")
parser.add_argument("-o", type=str, dest="offset_dir", action="store", help="Directory where computed offset will be outputed")

args = parser.parse_args()

def merge_file(src_trace1, trace1, src_trace2, trace2, dest_merge, dest_offset, dest_adjusted, dest_merge_adjusted):
    
    match = SequenceMatcher(None, trace1, trace2).find_longest_match(0, len(trace1), 0, len(trace2))
    common = trace1[match.a: match.a+match.size] 

    cap_1 = src_trace1 + "/" + trace1
    cap_2 = src_trace2 + "/" + trace2 

    merge_name = dest_merge + "/" + common + "_merge.pcap"
    cmd = ["mergecap", "-w", merge_name, cap_1, cap_2]
    output = subprocess.check_output(cmd)  

    offset_name = dest_offset + "/" + common + "_merge.txt"
    cmd = ["python", "compute_offset.py", "-f1", merge_name, "-f2", cap_2, "-o", offset_name ]
    output = subprocess.check_output(cmd)

    adjusted_name = dest_adjusted + "/" + trace1 + "_adjusted.pcap"
    cmd = ["./bin/shift_time", "-i", cap_1, "-f", offset_name, "-o", adjusted_name]
    output = subprocess.check_output(cmd)

    merge_adjusted_name = dest_merge_adjusted + "/" + common + "_merge_adjusted.pcap"
    cmd = ["mergecap", "-w", merge_adjusted_name, adjusted_name, cap_2]
    output = subprocess.check_output(cmd)

    reorder_name = merge_adjusted_name[0:-5] + "_re.pcap"
    cmd = ["reordercap", "-n", merge_adjusted_name, reorder_name]
    output = subprocess.check_output(cmd)

    os.remove(merge_adjusted_name)
    os.rename(reorder_name, merge_adjusted_name)

dir_shut1 = sorted(os.listdir(args.shut1))
dir_shut2 = sorted(os.listdir(args.shut2))


for trace1,trace2 in itertools.izip_longest(dir_shut1, dir_shut2, fillvalue=''):
    
    if trace1 != '' and trace2 != '':
        merge_file(args.shut1, trace1, args.shut2, trace2, args.merge_dir, args.offset_dir, args.adjusted_dir, args.merge_adjusted_dir)
