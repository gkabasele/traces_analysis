import os
import struct
import argparse
import numpy as np
from datetime import datetime
from datetime import timedelta
from itertools import izip_longest
from collections import OrderedDict
from ipaddress import IPv4Address, ip_address, ip_network


class FlowStatReader(object):

    def __init__(self, mode):
        self.mode = "rb" if mode == "bin" else "r"
        self.index = 0
        self.line_index = 0
        self.current_file = None
        self.finish = False
        self.filesize = 0

    def open_file(self, filename):
        self.current_file = open(filename, self.mode)
        self.index = 0
        self.line_index = 0
        self.filesize = os.path.getsize(filename)

    def close_file(self):
        self.current_file.close()
        self.current_file = None
        self.finish = False

    def read_binary(self, _type, readsize):
        self.index += readsize
        return struct.unpack(_type, self.current_file.read(readsize))[0]

    def change_ip(self, address, addr_iter, flowdict):
        if address in flowdict:
            return address, flowdict[address]
        else:
            res = next(addr_iter)
            return address, res

    def read_flow_binary(self, addr_iter, flowdict):
        addr = IPv4Address(self.read_binary('>I', 4))
        srcip, mod_src = self.change_ip(addr, addr_iter, flowdict)
        addr = IPv4Address(self.read_binary('>I', 4))
        dstip, mod_dst = self.change_ip(addr, addr_iter, flowdict)
        sport = self.read_binary('H', 2)
        dport = self.read_binary('H', 2)
        proto = self.read_binary('B', 1)
        self.read_binary('BBB', 3) # Padding

        size = self.read_binary('Q', 8)
        nb_pkt = self.read_binary('Q', 8)

        first_sec = self.read_binary('Q', 8)
        first_micro = self.read_binary('Q', 8)
        timestamp = datetime.fromtimestamp(first_sec)
        first = timestamp + timedelta(microseconds=first_micro)

        duration = (self.read_binary('f', 4))/float(1000)

        size_list = self.read_binary('Q', 8)

        pkt_dist = []
        while size_list > 0:
            val = self.read_binary('H', 2)
            pkt_dist.append(val)
            size_list -= 1

        size_list = self.read_binary('Q', 8)
        arr_dist = []
        while size_list > 0:
            val = self.read_binary('f', 4)
            arr_dist.append(val)
            size_list -= 1

        self.finish = self.index >= self.filesize
        return (srcip, mod_src, dstip, mod_dst, sport, dport, proto, size,
                nb_pkt, first, duration, pkt_dist, arr_dist)

    def readline_text(self):
        line = self.current_file.readline()
        self.line_index += 1
        return line

    def read_flow_text(self, addr_iter, flowdict):
        line = self.readline_text()
        self.finish = line == ''
        if not self.finish:
            (srcip, dstip, sport, dport, proto,
             size, nb_pkt, first, duration) = (None, None, None, None,
                                               None, None, None, None, None)
            mod_src, mod_dst = None, None
            pkt_dist, arr_dist = None, None
            if self.line_index != 0:
                if self.line_index % 3 == 2:
                    (srcip, dstip, sport, dport, proto,
                     size, nb_pkt, first, duration) = self.parse_flowkey(line)

                line = self.readline_text()
                if self.line_index % 3 == 0:
                    _, pkt_dist = self.parse_ps(line, int)

                line = self.readline_text()

                if self.line_index % 3 == 1:
                    _, arr_dist = self.parse_ipt(line)

                src_addr = IPv4Address(unicode(srcip))
                dst_addr = IPv4Address(unicode(dstip))
                src, mod_src = self.change_ip(src_addr, addr_iter, flowdict)
                dst, mod_dst = self.change_ip(dst_addr, addr_iter, flowdict)

                return (src, mod_src, dst, mod_dst, sport, dport, proto, size, nb_pkt, first,
                        duration, pkt_dist, arr_dist)

    def parse_flowkey(self, line):
        res = line.rstrip().split("\t")
        srcip, dstip, sport, dport, proto, size, nb_pkt, first, last, duration = res
        first = datetime.strptime(first, "%Y-%m-%d %H:%M:%S.%f")
        return (srcip, dstip, sport, dport, proto, int(size), int(nb_pkt),
                first, float(duration)/1000)

    def parse_ps(self, line, _type):
        nbr, tmp = line.split("\t")
        l = tmp.split(",")
        ps = [_type(x) for x in l[:-1]]
        return int(nbr), ps

    def parse_ipt(self, line):
        return self.parse_ps(line, float)


def display_hourly_to_file(hour, pkt_avg, ipt_avg):
    for (f1, f2, f3), (hour, ps, ipt) in (izip_longest(izip_longest(hour.keys(), pkt_avg.keys(), ipt_avg.keys()),
        izip_longest(hour.values(), pkt_avg.values(), ipt_avg.values()))):

        line = "{}: {}\n".format(f1, hour)
        print line
        line = "{}: {}\n".format(f2, ps)
        print line
        line = "{}: {}\n".format(f3, ipt)
        print line

def export_hourly_to_file(hour, pkt_avg, ipt_avg, filename):
    with open(filename, "w") as f:
        for (f1, f2, f3), (hour, ps, ipt) in (izip_longest(izip_longest(hour.keys(), pkt_avg.keys(), ipt_avg.keys()),
            izip_longest(hour.values(), pkt_avg.values(), ipt_avg.values()))):

            line = "{}: {}\n".format(f1, hour)
            f.write(line)
            line = "{}: {}\n".format(f2, ps)
            f.write(line)
            line = "{}: {}\n".format(f3, ipt)
            f.write(line)

def flow_info(srcip, dstip, sport, dport, proto, size, nb_pkt, first, duration,
              pkt_dist, arr_dist):
    s = "{}\t{}\t{}\t{}\t{}\t".format(srcip, dstip, sport, dport, proto)
    s += "{}\t{}\t{}\t{}\n".format(size, nb_pkt, first, duration)
    s += "{}\n{}\n".format(pkt_dist, arr_dist)
    return s

def main(textdir, bindir):
    prefixv4_txt = ip_network(unicode("10.0.0.0/16")).hosts()
    flowdict_txt = OrderedDict()
    readertxt = FlowStatReader("txt")
    txt_file = open("txt_reader.txt", "w")

    prefixv4_bin = ip_network(unicode("10.0.0.0/16")).hosts()
    flowdict_bin = OrderedDict()
    readerbin = FlowStatReader("bin")
    bin_file = open("bin_reader.txt", "w")

    for binname, textname  in zip(os.listdir(bindir), os.listdir(textdir)):
        binfilename = os.path.join(bindir, binname)
        textfilename = os.path.join(textdir, textname)
        readerbin.open_file(binfilename)
        readertxt.open_file(textfilename)

        readertxt.readline_text()
        while not readertxt.finish:
            res = readertxt.read_flow_text(prefixv4_txt, flowdict_txt)
            if not res:
                continue
            (srcip, modsrcip, dstip, moddstip, sport, dport, proto, size,
             nb_pkt, first, duration, pkt_dist, arr_dist) = res
            flowdict_txt[srcip] = modsrcip
            flowdict_txt[dstip] = moddstip
            s = flow_info(modsrcip, moddstip, sport, dport, proto, size,
                          nb_pkt, first, duration, pkt_dist, arr_dist)
            txt_file.write(s)

        while not readerbin.finish:
            (srcip, modsrcip, dstip, moddstip, sport, dport, proto, size,
             nb_pkt, first, duration, pkt_dist, arr_dist) = readerbin.read_flow_binary(prefixv4_bin, flowdict_bin)
            flowdict_bin[srcip] = modsrcip
            flowdict_bin[dstip] = moddstip
            s = flow_info(modsrcip, moddstip, sport, dport, proto, size,
                          nb_pkt, first, duration, pkt_dist, arr_dist)
            bin_file.write(s)

        readerbin.close_file()
        readertxt.close_file()

    bin_file.close()
    txt_file.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--textdir", type=str, dest="text", action="store")
    parser.add_argument("--bindir", type=str, dest="bin", action="store")

    args = parser.parse_args()

    textdir = args.text
    bindir = args.bin

    main(textdir, bindir)
