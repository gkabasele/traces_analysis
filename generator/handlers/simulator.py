import os
import time
import pdb
from collections import OrderedDict
from datetime import datetime
from datetime import timedelta
from flows import Flow

HEADER_SIZE = 14 + 20 + 32

class Stats(object):

    def __init__(self):

        self.nb_pkt = 0
        self.size = 0
        self.first = None
        self.last = None

    def update(self, nb_pkt, size, first, dur):

        self.nb_pkt += nb_pkt
        self.size += size + (nb_pkt * HEADER_SIZE)
        if not self.first:
            self.first = first
            self.last = self.first + timedelta(seconds=dur/1000.0)
        else:
            self.last = self.last + timedelta(seconds=dur/1000.0)

class Simulator(object):

    def __init__(self, flow, filename, timeseries):

        self.file = open(filename, "w")
        self.timeseries_file = open(timeseries, "w")

        self.hourly_nb_pkt = []
        self.hourly_size = []
        self.ps_timeseries = []
        self.ipt_timesereries = []

        self.rev_hourly_nb_pkt = []
        self.rev_hourly_size = []
        self.rev_ps_timeseries = []
        self.rev_ipt_timeseries = []

        self.target_flow = flow

        self.flows = OrderedDict()

        header = "SIP\tDIP\tSPORT\tDPORT\tPROTO\t#PKTS\tSIZE\tFIRST\tLAST\tDUR\n"
        self.file.write(header)

    def write_flow(self, flow):

        if flow not in self.flows:
            self.flows[flow] = Stats()

        if flow.key.get_reverse() not in self.flows:
            self.flows[flow.key.get_reverse()] = Stats()

        stats = self.flows[flow]

        try:
            pkt_dist = flow.generate_client_pkts(flow.nb_pkt)
            arr_dist = flow.generate_client_arrs(flow.nb_pkt)
        except Exception as err: 
            print err
            pdb.set_trace()

        if arr_dist == [] and flow.nb_pkt != 0:
            pdb.set_trace()

        size = sum(pkt_dist)
        dur = sum(arr_dist)

        if not stats.first:
            first = datetime.fromtimestamp(time.time())
        else:
            first = None

        stats.update(flow.nb_pkt, size, first, dur)

        if flow.key == self.target_flow:
            self.ps_timeseries.extend(pkt_dist)
            self.ipt_timesereries.extend(arr_dist)
            self.hourly_nb_pkt.append(flow.nb_pkt)
            self.hourly_size.append(size)

        rev_stats = self.flows[flow.key.get_reverse()]
        try:
            pkt_dist = flow.generate_server_pkts(flow.in_nb_pkt)
            arr_dist = flow.generate_server_arrs(flow.in_nb_pkt)
        except Exception as err:
            print err
            pdb.set_trace()

        if arr_dist == [] and flow.in_nb_pkt != 0:
            pdb.set_trace()

        size = sum(pkt_dist)
        dur = sum(arr_dist)

        if not rev_stats.first:
            first = datetime.fromtimestamp(time.time())
        else:
            first = None

        rev_stats.update(flow.in_nb_pkt, size, first, dur)

        if flow.key == self.target_flow:
            self.rev_ps_timeseries.extend(pkt_dist)
            self.rev_ipt_timeseries.extend(arr_dist)
            self.rev_hourly_nb_pkt.append(flow.in_nb_pkt)
            self.rev_hourly_size.append(size)

    def write_timeseries_to_file(self, timeseries):
        for value in timeseries[:-1]:
            self.timeseries_file.write("{}\t".format(value))
        self.timeseries_file.write("{}\n".format(timeseries[-1]))

    def export(self):
        for k, v in self.flows.items():
            dur = (v.last - v.first).total_seconds() * 1000.0
            first = v.first.strftime("%Y-%m-%d %H:%M:%S")
            last = v.last.strftime("%Y-%m-%d %H:%M:%S")

            line = "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\n".format(k.srcip,
                                                                     k.dstip,
                                                                     k.sport,
                                                                     k.dport,
                                                                     k.proto,
                                                                     v.nb_pkt,
                                                                     v.size, first,
                                                                     last, dur)
            self.file.write(line)

        self.timeseries_file.write(str(self.target_flow))
        self.timeseries_file.write("\n")

        self.write_timeseries_to_file(self.hourly_nb_pkt)
        self.write_timeseries_to_file(self.hourly_size)
        self.write_timeseries_to_file(self.ipt_timesereries)
        self.write_timeseries_to_file(self.ps_timeseries)

        self.timeseries_file.write(str(self.target_flow.get_reverse()))
        self.timeseries_file.write("\n")

        self.write_timeseries_to_file(self.rev_hourly_nb_pkt)
        self.write_timeseries_to_file(self.rev_hourly_size)
        self.write_timeseries_to_file(self.rev_ipt_timeseries)
        self.write_timeseries_to_file(self.rev_ps_timeseries)

    def stop(self):
        self.export()
        self.file.close()
        self.timeseries_file.close()
