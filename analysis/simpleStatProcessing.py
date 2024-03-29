import argparse
import pdb
import re
import matplotlib.pyplot as plt
import numpy as np

from process_stats import divide_by

RE = r"(?P<src>\d*\.\d*\.\d*\.\d*):(?P<sport>\d*)<-->(?P<dst>\d*\.\d*\.\d*\.\d*):(?P<dport>\d*)"
regex = re.compile(RE)


class SimpleStat(object):

    def __init__(self, srcip, dstip, sport, dport, pkt_per_hour, 
                 byte_per_hour, inter_ts, pkt_size_ts):

        self.srcip = srcip
        self.dstip = dstip
        self.sport = sport
        self.dport = dport
        self.pkt_hourly = pkt_per_hour
        self.byte_hourly = byte_per_hour
        self.inter_ts = inter_ts
        self.pkt_size_ts = pkt_size_ts

    def __hash__(self):
        return hash((self.srcip, self.sport, self.dstip, self.dport))

    def __str__(self):
        return "{}:{}<-->{}:{}".format(self.srcip, self.sport, self.dstip,
                                       self.dport)
    def __repr__(self):
        return self.__str__()


def parse_flow_block(lines):
    flow_id = (lines[0].split())[0]
    res = regex.match(flow_id).groups()
    if res is not None:
        srcip, sport, dstip, dport = res 
        pkt_per_hour = [int(x) for x in lines[1].split()]
        byte_per_hour = [int(x) for x in lines[2].split()]
        inter_ts = [int(x) for x in lines[3].split()]
        pkt_size_ts = [int(x) for x in lines[4].split()]

        return SimpleStat(srcip, dstip, int(sport), int(dport), pkt_per_hour,
                          byte_per_hour, inter_ts, pkt_size_ts)

    else:
        raise ValueError("Could not get the flow identifier")


def create_stats(infile):
    all_stats = {}
    with open(infile, "r") as fname:
        block = []
        for i, line in enumerate(fname):
            if i % 5 != 0 or i == 0:
                block.append(line)
            else:
                stats = parse_flow_block(block)
                all_stats[hash(stats)] = stats
                block = [line]
        stats = parse_flow_block(block)
        all_stats[hash(stats)] = stats
    return all_stats


def comparitive_cdf(values_a, values_b, filename, xlabel, div=1, log=False):
    vals_a = divide_by(values_a, div)
    data_real = np.sort(vals_a) 
    counts, bin_edges = np.histogram(data_real, bins=100, density=True)
    cdf = np.cumsum(counts)
    plt.plot(bin_edges[1:], cdf/cdf[-1], label="real")
    plt.ticklabel_format(useOffset=False, style="plain")

    vals_b = divide_by(values_b, div)
    data_gen = np.sort(vals_b)
    counts, bin_edges = np.histogram(data_gen, bins=100, density=True)
    cdf = np.cumsum(counts)
    plt.plot(bin_edges[1:], cdf/cdf[-1], label="gen")
    plt.ticklabel_format(useOffset=False, style="plain")

    if log:
        plt.xscale("log")
    plt.xlabel(xlabel)
    plt.ylabel("CDF")
    plt.savefig(filename)
    plt.close()

    
def print_line(value_a, value_b):
    print("\t{}\t\t{}\t".format(value_a, value_b))

def display_comparison(real, gen):
    print("\t\t\tREAL\t\t\t\t\t\tGEN")
    print_line(real, gen)
    print("\t")
    print("Interarrival")
    print_line("Mn:{}, Sd:{}".format(np.mean(real.inter_ts),
                                     np.std(real.inter_ts)),
               "Mn:{}, Sd:{}".format(np.mean(gen.inter_ts),
                                     np.std(gen.inter_ts)))
    print("\t")
    print("Packet Size")
    print_line("Mn:{}, Sd:{}".format(np.mean(real.pkt_size_ts),
                                     np.std(real.pkt_size_ts)),
               "Mn:{}, Sd:{}".format(np.mean(gen.pkt_size_ts),
                                     np.std(gen.pkt_size_ts)))
    print("\t")


def compare_stats(map_ip, real_stats, gen_stats):

    for k, stats in real_stats.iteritems():
        key = hash((map_ip[stats.srcip], stats.sport, map_ip[stats.dstip],
                    stats.dport))
        try:
            cand_flow = gen_stats[key]
            display_comparison(stats, cand_flow)
            filename = "{}_interarrival.png".format(cand_flow)
            comparitive_cdf(stats.inter_ts, cand_flow.inter_ts, filename,
                            "Inter-Packet Time (Sec)", 1000)
            filename = "{}_pkt_size_ts.png".format(cand_flow)
            comparitive_cdf(stats.pkt_size_ts, cand_flow.pkt_size_ts,
                            filename, "Packet Size (B)")

        except KeyError:
            print("Could not find matching flow for " + str(stats))
            

def main(real_infile, gen_infile, map_ip):
    real_stats = create_stats(real_infile)
    gen_stats = create_stats(gen_infile)
    mapping = {}
    with open(map_ip, "r") as fname:
        for line in fname:
            real, gen = line.split()
            mapping[real] = gen

    compare_stats(mapping, real_stats, gen_stats)
    

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--real", action="store", dest="real_infile",
                        help="File containing the timeseries of the real trace")
    parser.add_argument("--gen", action="store", dest="gen_infile",
                        help="File containing the timeseries of the gen trace")
    parser.add_argument("--map", action="store", dest="map_ip",
                        help="File with mapping of the real ip and gen ip")

    args = parser.parse_args()
    main(args.real_infile, args.gen_infile, args.map_ip)
