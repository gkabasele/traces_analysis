import sys
import subprocess
import os
import argparse
import itertools
from difflib import SequenceMatcher

# This script is needed because for some obscure reasons, some pcap file are empty when merged
# so we remerge empty file

parser = argparse.ArgumentParser()
parser.add_argument("-s1", type=str, dest="shut1", action="store", help="Directory containing the trace from shuttle 1")
parser.add_argument("-s2", type=str, dest="shut2", action="store", help="Directory containing the trace from shuttle 2")
parser.add_argument("-m", type=str, dest="merge", action="store", help="Directory containing merge trace")
parser.add_argument("-su", type=str, dest="suffix", action="store", help="suffix to add to the string")


args = parser.parse_args()

COMMON_LABEL_SIZE = len('2018-09-21:14')
FULL_FILENAME_SIZE = len('2018-09-21:14:03:_merge_adjusted.pcap')

def remerge_empty_file(src1, dir_shut1, src2, dir_shut2, merge, trace_m): 
    for trace1, trace2 in itertools.izip_longest(dir_shut1, dir_shut2, fillvalue=""):
        if (trace_m[0:COMMON_LABEL_SIZE] == trace1[0:COMMON_LABEL_SIZE] and 
                trace_m[0:COMMON_LABEL_SIZE] == trace2[0:COMMON_LABEL_SIZE]):
            cap_1 = src1 + "/" + trace1
            cap_2 = src2 + "/" + trace2
            cap_m = merge + "/" + trace_m[0:COMMON_LABEL_SIZE] + "_merge_adjusted.pcap"
            cmd = ["mergecap","-w", cap_m, cap_1, cap_2]
            output = subprocess.check_output(cmd)

            reorder_name = cap_m[0:-5] + "_re.pcap"
            cmd = ["reordercap", "-n", cap_m, reorder_name]
            output = subprocess.check_output(cmd)
            
            file_info = os.stat(reorder_name)
            if file_info.st_size < 1024:
                os.remove(reorder_name)
            else:
                os.remove(cap_m)
                os.rename(reorder_name, cap_m)

        
#dir_shut1 = sorted(os.listdir(args.shut1))
#dir_shut2 = sorted(os.listdir(args.shut2))
dir_merge = sorted(os.listdir(args.merge))

for trace_m in dir_merge:
    #file_info = os.stat(args.merge + "/" + trace_m)
    #if file_info.st_size < 1024:
    #    remerge_empty_file(args.shut1, dir_shut1, args.shut2, dir_shut2, args.merge, trace_m)
    if len(trace_m) < FULL_FILENAME_SIZE:
        oldname = args.merge + '/' + trace_m
        newname = args.merge + '/' + trace_m[0:COMMON_LABEL_SIZE] + args.suffix + trace_m[COMMON_LABEL_SIZE:]
        os.rename(oldname, newname)

