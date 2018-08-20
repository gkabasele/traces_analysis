import sys
import subprocess
import argparse
import os
import itertools


parser = argparse.ArgumentParser()
parser.add_argument("-s1", type=str, dest="shut1", action="store", help="Directory containing the trace from shuttle 1")
parser.add_argument("-s2", type=str, dest="shut2", action="store", help="Directory containing the trace from shuttle 2")
parser.add_argument("-m", type=str, dest="merge_dir", action="store", help="Directory where merge will be outputed")
parser.add_argument("-a", type=str, dest="adjusted_dir", action="store", help="Directory where adjusted will be outputed")
parser.add_argument("-ma", type=str, dest="merge_adjusted_dir", action="store", help="Directory where merge adjusted will be outputed")
parser.add_argument("-o", type=str, dest="offset_dir", action="store", help="Directory where computed offset will be outputed")
parser.add_argument("-c", type=str, dest="command", action="store", help="command to run")

args = parser.parse_args()


dir_shut1 = sorted(os.listdir(args.shut1))
dir_shut2 = sorted(os.listdir(args.shut2))

for trace1,trace2 in itertools.izip_longest(dir_shut1, dir_shut2, fillvalue=''):
    
    if trace1 != '' and trace2 != '':
        cmd = [args.command, trace1, trace2, args.merge_dir, args.offset_dir, args.adjusted_dir, args.merge_adjusted_dir]
#        output = subprocess.check_output(cmd)

    print cmd





