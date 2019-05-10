import os
import argparse
import numpy as np
from itertools import izip_longest
from collections import OrderedDict

parser = argparse.ArgumentParser()
parser.add_argument("--indir", type=str, dest="indir", action="store")
parser.add_argument("--outfile", type=str, dest="outfile", action="store")

args = parser.parse_args()

indir = args.indir
outfile = args.outfile

def parse_flowkey(line):
    srcip, dstip, sport, dport, proto , _, _, _, _, _ = line.split("\t")
    return srcip, dstip, sport, dport, proto
 
def parse_ps(line, _type):
    nbr, tmp = line.split("\t")
    l = tmp.split(",") 
    ps = [_type(x) for x in l[:-1]]
    return int(nbr), ps

def parse_ipt(line):
    return parse_ps(line, float) 
    # return ipt

def export_hourly_to_file(hour, pkt_avg, ipt_avg, filename):
    with open(filename, "w") as f:
        for (f1, f2, f3), (hour, ps, ipt) in (izip_longest(izip_longest(hour.keys(), pkt_avg.keys(), ipt_avg.keys),
          izip_longest(hour.values(), pkt_avg.values(), ipt_avg.values()))):

          line = "{}: {}\n".format(f1, hour)
          f.write(line)
          line = "{}: {}\n".format(f2, ps)
          f.write(line)
          line = "{}: {}\n".format(f3, ipt)

if __name__ == "__main__":
    hours = len(os.listdir(indir))
    
    if os.path.exist(outfile): 
        os.remove(outfile) 
    #size
    flows_hour = OrderedDict()
    flows_pkt_avg = OrderedDict()
    flows_ipt_avg = OrderedDict() 
    
    for h in os.listdir:
        filename = os.path.join(indir, h)
        with open(filename, "r") as f:
            flowkey = None
            ps = None
            ipt = None
            for i, line in enumerate(f):
                if i % 3 == 1:
                    assert not (flowkey and ps and ipt)
                    srcip, dstip, sport, dport, proto = parse_flowkey(line)
                    flowkey = (srcip, dstip, sport, dport, proto)
                elif i % 3 == 2:
                     _, ps = parse_ps(line, int)
                elif i % 3 == 0 and i !=0:      
                  _, ipt = parse_ipt(line)
                  size = np.sum(ps)
                  flow_ps_avg = np.average(ps)
                  flow_ipt_avg = np.average(ipt)
    
                  if flowkey not in flows_hour:
                      flows_hour[flowkey] = [size]
                  else:
                      flows_hour[flowkey].append(size)
    
                  if flowkey not in flows_pkt_avg:
                      flows_pkt_avg[flowkey] = [flow_ps_avg]
                  else:
                      flows_pkt_avg[flowkey].append(flow_ps_avg)
    
                  if flowkey not in flows_ipt_avg:
                      flows_ipt_avg[flowkey] = [flow_ipt_avg]
                  else:
                      flows_ipt_avg[flowkey].append(flow_ipt_avg)  
                  flowkey = None
                  ps = None
                  ipt = None
