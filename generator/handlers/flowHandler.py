#!/usr/bin/python
import struct
import sys
import os
import argparse
import time
import subprocess
import random as rm
import pickle
import errno
import pdb
import tempfile
from threading import RLock
from datetime import datetime
from datetime import timedelta
from collections import OrderedDict
from ipaddress import IPv4Address, ip_network, ip_address
import yaml
import numpy as np
import scipy.stats as stats
from scipy.stats.kde import gaussian_kde
from sklearn.mixture import GaussianMixture
from sklearn.neighbors import KernelDensity
from mininet.net import Mininet
from mininet.clean import cleanup, sh
from mininet.cli import CLI

import util 
from flows import Flow, FlowKey, FlowCategory
from flows import DiscreteGen, ContinuousGen
from simulator import Simulator
from networkHandler import LocalHandler, NetworkHandler, GenTopo
from flowStatReader import FlowStatReader

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--conf", type=str, dest="config", action="store")
    parser.add_argument("--debug", dest="debug", action="store_true")
    parser.add_argument("--mode", choices=["mininet", "local"])
    parser.add_argument("--read", choices=["bin", "text"])
    parser.add_argument("--saveflow")
    parser.add_argument("--loadflow")
    parser.add_argument("--savedist")
    parser.add_argument("--loaddist")
    parser.add_argument("--numflow", type=int, dest="numflow", action="store")
    args = parser.parse_args()

def swap_bytes(array, swap_size):
    res = bytearray(len(array))
    res[:swap_size] = array[swap_size:]
    res[swap_size:] = array[:swap_size]
    return res

def substract_time(t1, t2):
    if t2 >= t1:
        res = (t2 - t1).total_seconds
        return res
    raise ValueError("%s is before %s "% (t2, t1))


class FlowHandler(object):

    # Nb iteration to test MSE
    NB_ITER = 10
    NB_CLUSTER = 5
    MIN_DIST = 0.2
    # Minimum sample size for to consider continuous
    MIN_SAMPLE_SIZE = 50

    """
        This is the main class coordinating the creation/deletion of flows
    """

    def __init__(self, config, mode="mininet", read="bin", saveflow=None, loadflow=None,
                 savedist=None, loaddist=None):

        with open(config, 'r') as stream:
            try:
                conf = yaml.load(stream)
                self.dir = conf['input']
                self.dir_stats = util.sorted_nicely((os.listdir(conf['input'])))
                self.frame_index = 0
                filename = os.path.join(self.dir, self.dir_stats[self.frame_index])
                appli = conf['application']
                self.output = conf['output']
                self.subnet = conf['prefixv4']
                self.keep_emp = conf['storeEmp']
                self.frame_size = int(conf['frameSize'])
                self.mininet_mode = mode == "mininet"
                self.slice_dist = conf['doDistance']
                self.slice_ks_thresh = conf['distanceThresh']
                self.file_mapping_ip = conf['mappingIP']
                self.do_attack = conf['doAttack']
                self.attack_frame = conf['attackFrame']
                self.read_mode = read
                if self.mininet_mode:
                    self.prefixv4 = ip_network(unicode(conf['prefixv4'])).hosts()
                else:
                    self.prefixv4 = ip_network(unicode("172.16.0.0/16")).hosts()

                if self.do_attack:
                    self.attack = conf['attack']
                else:
                    self.attack = None
                self.categories = {}
                # Keep category distribution
                self.category_dist = {}
                self.create_categorie(appli)
                self.mapping_address = {}
                # Lock assigned to a pipe
                self.pipelock = {}

                self.safe_mode = conf['safeMode']
                self.attacker_ip = None
                self.index = 0

                assert not ((loadflow is not None) and (saveflow is not None))
                assert not ((loaddist is not None) and (savedist is not None))

                if loadflow is not None:
                    input_pck = conf['input_flow']
                    with open(input_pck, 'rb') as fh:
                        self.flows = pickle.load(fh)
                elif saveflow is not None:
                    output_pck = conf['output_flow']
                    self.flows = self.retrieve_flows(filename, output_pck)
                else:
                    self.flows = self.retrieve_flows(filename)
                # Last category that was spawn
                self.last_cat = None

                # Last flow that were spawn
                self.last_flow = None

            except yaml.YAMLError as exc:
                print exc
                sys.exit()
            except AssertionError:
                print "Cannot load and save at the same time"
                sys.exit()

    def export_mapping_ip(self):
        with open(self.file_mapping_ip, 'w') as f:
            for k, v in self.mapping_address.items():
                line = "{}\t{}\n".format(k, v)
                f.write(line)

    def read(self, _type, readsize, f):
        self.index += readsize
        return struct.unpack(_type, f.read(readsize))[0]

    def change_ip(self, address):

        if address in self.mapping_address:
            return self.mapping_address[address]
        else:
            res = next(self.prefixv4)
            self.mapping_address[address] = res
            return res

    def get_flow_key(self, srcip, dstip, sport, dport, proto, first):
        # Service running in the trace must be on server side
        client_flow = None
        server_flow = None
        if sport in self.categories:
            client_flow = FlowKey(dstip, srcip, dport, sport, proto, None, sport)
            server_flow = FlowKey(srcip, dstip, sport, dport, proto, first, sport)
        elif dport in self.categories:
            client_flow = FlowKey(srcip, dstip, sport, dport, proto, first, dport)
            server_flow = FlowKey(dstip, srcip, dport, sport, proto, None, dport)

        if server_flow is None and client_flow is None:
            client_flow = FlowKey(srcip, dstip, sport, dport, proto, first, 0)
            server_flow = FlowKey(dstip, srcip, dport, sport, proto, None, 0)

        return (server_flow, client_flow)

    def read_flow(self, f):
        addr = IPv4Address(self.read('>I', 4, f))
        srcip = self.change_ip(addr)
        addr = IPv4Address(self.read('>I', 4, f))
        dstip = self.change_ip(addr)
        sport = self.read('H', 2, f)
        dport = self.read('H', 2, f)
        proto = self.read('B', 1, f)
        self.read('BBB', 3, f) # Padding

        size = self.read('Q', 8, f)
        nb_pkt = self.read('Q', 8, f)

        first_sec = self.read('Q', 8, f)
        first_micro = self.read('Q', 8, f)
        timestamp = datetime.fromtimestamp(first_sec)
        first = timestamp + timedelta(microseconds=first_micro)

        duration = (self.read('f', 4, f))/float(1000)

        size_list = self.read('Q', 8, f)

        pkt_dist = []
        while size_list > 0:
            val = self.read('H', 2, f)
            pkt_dist.append(val)
            size_list -= 1

        size_list = self.read('Q', 8, f)
        arr_dist = []
        while size_list > 0:
            val = self.read('f', 4, f)
            arr_dist.append(val)
            size_list -= 1
        return (srcip, dstip, sport, dport, proto, size,
                nb_pkt, first, duration, pkt_dist, arr_dist)

    def retrieve_flows(self, filename, output_pck=None):
        flows = OrderedDict()
        with open(filename, "rb") as f:
            filesize = os.path.getsize(filename)
            self.index = 0
            while self.index < filesize:
                (srcip, dstip, sport, dport, proto, size, nb_pkt, first,
                 duration, pkt_dist, arr_dist) = self.read_flow(f)

                cur_flow = None

                srv_flow, clt_flow = self.get_flow_key(srcip, dstip, sport, dport,
                                                       proto, first)

                flow_cat = self.category_dist[clt_flow.cat]
                if not (clt_flow in flows or srv_flow in flows):
                    if clt_flow.first is not None:
                        flow = Flow(clt_flow, duration, size, nb_pkt,
                                    keep_emp=self.keep_emp, pkt_dist=pkt_dist, arr_dist=arr_dist)
                        flow.emp_arr = sum(arr_dist)
                        flows[clt_flow] = flow
                        self.estimate_distribution(flow, pkt_dist, arr_dist, FlowHandler.NB_ITER)
                        cur_flow = flow

                    elif srv_flow.first is not None:
                        flow = Flow(srv_flow, duration, size, nb_pkt,
                                    keep_emp=self.keep_emp, pkt_dist=pkt_dist,
                                    arr_dist=arr_dist, client_flow=False)
                        flow.emp_arr = sum(arr_dist)
                        flows[srv_flow] = flow
                        self.estimate_distribution(flow, pkt_dist, arr_dist, FlowHandler.NB_ITER)
                        cur_flow = flow
                    else:
                        raise ValueError("Invalid time for flow first appearance")

                elif clt_flow in flows:
                    # If source ip are different, then its a server flow of an
                    # already known flow
                    if srcip != clt_flow.srcip:
                        flow = flows[clt_flow]
                        flow.set_reverse_stats(duration, size, nb_pkt, first,
                                               keep_emp=self.keep_emp,
                                               pkt_dist=pkt_dist,
                                               arr_dist=arr_dist)
                        flow.in_emp_arr = sum(arr_dist)
                        self.estimate_distribution(flow, pkt_dist, arr_dist, FlowHandler.NB_ITER,
                                                   clt=False)
                        flow_cat.add_flow_client(flow.size, flow.nb_pkt,
                                                 flow.dur)
                        flow_cat.add_flow_server(size, nb_pkt, duration)
                        cur_flow = flow
                elif srv_flow in flows:
                    if srcip != srv_flow.srcip:
                        flow = flows[srv_flow]
                        flow.set_reverse_stats(duration, size, nb_pkt, first,
                                               keep_emp=self.keep_emp,
                                               pkt_dist=pkt_dist,
                                               arr_dist=arr_dist)
                        flow.in_emp_arr = sum(arr_dist)
                        self.estimate_distribution(flow, pkt_dist, arr_dist, FlowHandler.NB_ITER,
                                                   clt=False)
                        flow_cat.add_flow_client(size, nb_pkt, duration)
                        flow_cat.add_flow_server(flow.size, flow.nb_pkt,
                                                 flow.dur)
                        cur_flow = flow

                assert flow.estim_arr is not None and flow.estim_pkt is not None

                src_pipe, dst_pipe = self.create_flow_pipename(cur_flow)
                self.create_pipe(src_pipe, dst_pipe)

        if output_pck is not None:
            with open(output_pck, 'wb') as fhr:
                pickle.dump(flows, fhr)

        return flows

    def get_next_frame_flow(self):
        next_frame_flow = set()
        if self.frame_index < len(self.dir_stats) - 1:
            filename = os.path.join(self.dir, self.dir_stats[self.frame_index +1])

            with open(filename, "rb") as f:
                filesize = os.path.getsize(filename)
                self.index = 0
                while self.index < filesize:
                    (srcip, dstip, sport, dport, proto, size, nb_pkt, first,
                     duration, pkt_dist, arr_dist) = self.read_flow(f)

                    srv_flow, clt_flow = self.get_flow_key(srcip, dstip, sport,
                                                           dport, proto, first)
                    next_frame_flow.add(srv_flow)
                    next_frame_flow.add(clt_flow)
        return next_frame_flow

    def create_flow_pipename(self, flow):
        tmpdir = tempfile.gettempdir()
        filename = "{}_{}:{}.flow".format(flow.srcip, flow.sport, flow.proto)
        src_pipe = os.path.join(tmpdir, filename)
        filename = "{}_{}:{}.flow".format(flow.dstip, flow.dport, flow.proto)
        dst_pipe = os.path.join(tmpdir, filename)
        return src_pipe, dst_pipe

    def get_stats_file(self):
        return os.path.join(self.dir, self.dir_stats[self.frame_index])

    # Modify emp_arr and in_emp_arr
    def is_flow_to_reestimate(self, flow, nb_pkt, pkt_dist, arr_dist,
                              clt=True):
        if clt:
            old_pkt_dist = flow.generate_client_pkts(nb_pkt)
        else:
            old_pkt_dist = flow.generate_server_pkts(nb_pkt)

        new_pkt_dist = pkt_dist

        reestimate_pkt = (len(new_pkt_dist) == len(old_pkt_dist))

        if reestimate_pkt:
            ks_pkt = util.distance_ks(old_pkt_dist, new_pkt_dist)
            reestimate_pkt = ks_pkt < self.slice_ks_thresh

        if clt:
            flow.emp_arr = sum(arr_dist)
        else:
            flow.in_emp_arr = sum(arr_dist)

        if clt:
            old_arr_dist = flow.generate_client_arrs(nb_pkt)
        else:
            old_arr_dist = flow.generate_server_arrs(nb_pkt)
        new_arr_dist = arr_dist

        reestimate_arr = (len(new_arr_dist) == len(old_arr_dist))
        if reestimate_arr:
            ks_arr = util.distance_ks(old_arr_dist, new_arr_dist)
            reestimate_arr = ks_arr < self.slice_ks_thresh

        return reestimate_pkt, reestimate_arr

    def update_flow(self, flowkey, duration, size, nb_pkt, first,
                    pkt_dist, arr_dist):

        flow = self.flows[flowkey]

        if self.slice_dist and flow.first_frame < self.frame_index:
            reestimate_pkt, reestimate_arr = self.is_flow_to_reestimate(flow,
                                                                        nb_pkt,
                                                                        pkt_dist,
                                                                        arr_dist)
        else: 
            reestimate_pkt, reestimate_arr = True, True

        flow.set_stats(duration, size, nb_pkt, first, keep_emp=self.keep_emp,
                       pkt_dist=pkt_dist, arr_dist=arr_dist)
        flow.last_frame = self.frame_index
        flow.emp_arr = sum(arr_dist)
        self.estimate_distribution(flow, pkt_dist, arr_dist,
                                   FlowHandler.NB_ITER, estpkt=reestimate_pkt,
                                   estarr=reestimate_arr)

    def update_reverse_stats(self, flowkey, duration, size, nb_pkt, first, 
                             pkt_dist, arr_dist):
        flow = self.flows[flowkey]
        if self.slice_dist and flow.first_frame < self.frame_index:
            reestimate_pkt, reestimate_arr = self.is_flow_to_reestimate(flow,
                                                                        nb_pkt,
                                                                        pkt_dist,
                                                                        arr_dist,
                                                                        clt=False)
        else:
            reestimate_pkt, reestimate_arr = True, True

        flow.set_reverse_stats(duration, size, nb_pkt, first,
                               keep_emp=self.keep_emp, pkt_dist=pkt_dist,
                               arr_dist=arr_dist)
        flow.last_frame = self.frame_index
        flow.in_emp_arr = sum(arr_dist)
        self.estimate_distribution(flow, pkt_dist, arr_dist,
                                   FlowHandler.NB_ITER, clt=False,
                                   estpkt=reestimate_pkt, estarr=reestimate_arr)

    def reset_flows(self):
        for k, v in self.flows.items():
            flow = self.flows[k]
            flow.reset()

    def reset_flows_for_dist(self):
        for k, v in self.flows.items():
            flow = self.flows[k]
            flow.reset_flow()

    def redefine_flows(self):
        self.reset_flows_for_dist()
        #self.reset_flows()
        filename = self.get_stats_file()
        order = OrderedDict()
        with open(filename, "rb") as f:
            filesize = os.path.getsize(filename)
            self.index = 0
            while self.index < filesize:
                (srcip, dstip, sport, dport, proto, size, nb_pkt, first,
                 duration, pkt_dist, arr_dist) = self.read_flow(f)

                cur_flow = None
                srv_flow, clt_flow = self.get_flow_key(srcip, dstip, sport,
                                                       dport, proto, first)

                if srv_flow.first is not None and clt_flow not in order:
                    order[srv_flow] = srv_flow
                elif clt_flow.first is not None and srv_flow not in order:
                    order[clt_flow] = clt_flow
                else:
                    pass

                flow_cat = self.category_dist[clt_flow.cat]

                # Flow discovered in previous time frame
                if (clt_flow in self.flows and
                        self.flows[clt_flow].first_frame < self.frame_index):

                    # Current unidirectional flow is the one in the dictionnary?
                    if clt_flow.srcip == srcip:
                        self.update_flow(clt_flow, duration, size,
                                         nb_pkt, first, pkt_dist, arr_dist)
                    else:
                        self.update_reverse_stats(clt_flow, duration, size,
                                                  nb_pkt, first, pkt_dist,
                                                  arr_dist)

                    flow = self.flows[clt_flow]

                if (srv_flow in self.flows and
                        self.flows[srv_flow].first_frame < self.frame_index):

                    if srv_flow.srcip == srcip:
                        self.update_flow(srv_flow, duration, size, nb_pkt,
                                         first, pkt_dist, arr_dist)
                    else:
                        self.update_reverse_stats(srv_flow, duration, size,
                                                  nb_pkt, first, pkt_dist,
                                                  arr_dist)

                    flow = self.flows[srv_flow]

                # Flow discovered in current frame
                # Totally new flow

                if not (clt_flow in self.flows or srv_flow in self.flows):
                    if clt_flow.first is not None:
                        tmp_flow = clt_flow
                    elif srv_flow.first is not None:
                        tmp_flow = srv_flow
                    else:
                        raise ValueError("Invalid time for first appearance")

                    client_flow = clt_flow.first is not None

                    flow = Flow(tmp_flow, duration, size, nb_pkt,
                                keep_emp=self.keep_emp, pkt_dist=pkt_dist,
                                arr_dist=arr_dist,
                                client_flow=client_flow,
                                first_frame=self.frame_index,
                                last_frame=self.frame_index)

                    flow.emp_arr = sum(arr_dist)
                    self.flows[tmp_flow] = flow
                    self.estimate_distribution(flow, pkt_dist, arr_dist,
                                               FlowHandler.NB_ITER)
                    cur_flow = flow
                # Flow in one direction has already been discovered
                else:
                    if clt_flow in self.flows:
                        if srcip != clt_flow.srcip:

                            self.update_reverse_stats(clt_flow, duration, size,
                                                      nb_pkt, first, pkt_dist,
                                                      arr_dist)
                            flow = self.flows[clt_flow]
                            flow_cat.add_flow_client(flow.size, flow.nb_pkt, flow.dur)
                            flow_cat.add_flow_server(size, nb_pkt, duration)

                            flow.in_emp_arr = sum(arr_dist)
                            cur_flow = flow
                    elif srv_flow in self.flows:
                        if srcip != srv_flow.srcip:
                            self.update_reverse_stats(srv_flow, duration, size,
                                                      nb_pkt, first, pkt_dist,
                                                      arr_dist)
                            flow = self.flows[srv_flow]
                            flow_cat.add_flow_client(size, nb_pkt, duration)
                            flow_cat.add_flow_server(flow.size, flow.nb_pkt,
                                                     flow.dur)
                            flow.in_emp_arr = sum(arr_dist)
                            cur_flow = flow
                if cur_flow:
                    src_pipe, dst_pipe = self.create_flow_pipename(cur_flow)
                    self.create_pipe(src_pipe, dst_pipe)

        self.clear_frame()
        return order.keys()

    def clear_frame(self):
        print "Clearing frame"
        for k, v in self.flows.items():
            if v.last_frame < self.frame_index:
                print "Removing flow {}".format(k)
                del self.flows[k]

    def create_pipe(self, src_pipe, dst_pipe):

        try:
            os.mkfifo(src_pipe)
            self.pipelock[src_pipe]= util.PipeLock()
        except OSError as err:
            if err.errno == errno.EEXIST:
                pass
            else:
                print "Could not create pipe {}".format(src_pipe)

        try:
            os.mkfifo(dst_pipe)
            self.pipelock[dst_pipe] = util.PipeLock()
        except OSError as err:
            if err.errno == errno.EEXIST:
                pass
            else:
                print "Could not create pipe {}".format(dst_pipe)

    def compute_flows_distances(self, fun, output_pck=None):
        '''
            fun is a distance function
        '''
        distances = OrderedDict()
        flowskey = self.flows.keys()

        norms = {}

        for i in range(len(flowskey)):
            flow = self.flows[flowskey[i]]
            hasrev = flow.in_arr_dist is not None
            distances[flow.key] = OrderedDict()

            if flow.key not in norms:
                norms[flow.key] = util.normalize_data(flow.arr_dist)

            if hasrev:
                revkey = flow.get_reverse()
                distances[revkey] = OrderedDict()

                if revkey not in norms:
                    norms[revkey] = util.normalize_data(flow.in_arr_dist)

                # computing distance with reverse flow
                d = fun(norms[flow.key], norms[revkey])
                #d = fun(flow.arr_dist, flow.in_arr_dist)
                distances[flow.key][revkey] = d

            for j in range(i+1, len(flowskey)):
                nextflow = self.flows[flowskey[j]]
                nexthasrev = nextflow.in_arr_dist is not None

                if nextflow.key not in norms:
                    norms[nextflow.key] = util.normalize_data(nextflow.arr_dist)

                d = fun(norms[flow.key], norms[nextflow.key])
                #d = fun(flow.arr_dist, nextflow.arr_dist)
                distances[flow.key][nextflow.key] = d

                if nexthasrev:
                    nextrevkey = nextflow.get_reverse()

                    if nextrevkey not in norms:
                        norms[nextrevkey] = util.normalize_data(nextflow.in_arr_dist)

                    d = fun(norms[flow.key], norms[nextrevkey])
                    #d = fun(flow.arr_dist, nextflow.in_arr_dist)
                    distances[flow.key][nextrevkey] = d

                    if hasrev:
                        d = fun(norms[revkey], norms[nextrevkey])
                        #d = fun(flow.in_arr_dist, nextflow.in_arr_dist)
                        distances[revkey][nextrevkey] = d

                if hasrev:
                    d = fun(norms[revkey], norms[nextflow.key])
                    #d = fun(flow.in_arr_dist, nextflow.arr_dist)
                    distances[revkey][nextflow.key] = d

        if output_pck is not None:
            with open(output_pck, 'wb') as fh:
                pickle.dump(distances, fh)

        return distances


    def create_categorie(self, appli):
        for k in appli:
            # random port following an application port
            self.categories[int(k)] = {}
            self.category_dist[int(k)] = FlowCategory(int(k))
        self.categories[0] = {}
        self.category_dist[0] = FlowCategory(0)

    def  _next_port_in_cat(self, next_sport, next_dport, randport):

        if next_sport in self.categories:
            return next_sport

        elif next_dport in self.categories:
            return next_dport
        else:
            return randport

    def _add_to_cat(self, cur_port, next_port, interflow):

        if next_port in self.categories[cur_port]:
            self.categories[cur_port][next_port][0] += 1
            self.categories[cur_port][next_port][1].append(interflow)
        else:
            self.categories[cur_port][next_port] = (1, [interflow])


    def compute_flow_corr(self):
        i = 0
        randport = 0
        flowseq = self.flows.keys()
        while i < len(flowseq) - 1:
            flow = self.flows[flowseq[i]]
            next_flow = self.flows[flowseq[i+1]] 
            cur_dport = flow.dport
            cur_sport = flow.sport
            next_dport = next_flow.dport
            next_sport = next_flow.sport

            interflow = (next_flow.first - flow.first).total_seconds() 

            if next_dport not in self.categories:
                next_dport = 0

            if next_sport not in self.categories:
                next_sport = 0

            if cur_dport in self.categories:
                port = self._next_port_in_cat(next_sport, next_dport, randport)
                self._add_to_cat(cur_dport, port, interflow)

            elif cur_sport in self.categories:
                port = self._next_port_in_cat(next_sport, next_dport, randport)
                self._add_to_cat(cur_sport, port, interflow)

            else:
                port = self._next_port_in_cat(next_sport, next_dport, randport)
                self._add_to_cat(randport, port, interflow)

            i += 1

        for k in self.categories:
            total = sum([x[0] for x in self.categories[k].values()])
            for c in self.categories[k]:
                val = self.categories[k][c][0]
                interflow = np.mean(self.categories[k][c][1])
                self.categories[k][c] = (val/float(total), interflow)

    def get_next_cat(self):
        if self.last_cat in self.categories:
            poss = self.categories[self.last_cat]
            cat = poss.keys()
            prob = [x[0] for x in poss.values()]
            new_cat = np.random.choice(cat, replace=True, p=prob)
            if new_cat != 0:
                waiting_time = poss[new_cat][1]
                self.last_cat = new_cat
                return new_cat, time
            else:
                waiting_time = poss[new_cat][1]
                self.last_cat = 0

                return rm.randint(1024, 65535), time

    def change_cat(self, flow):
        if flow.dport in self.categories:
            self.last_cat = flow.dport
        elif flow.sport in self.categories:
            self.last_cat = flow.sport
        else:
            self.last_cat = 0

    def get_flow_from_cat(self, cat):
        return filter(lambda x: x.cat == cat, self.flows.keys())

    @classmethod
    def clean_tmp(cls):
        tmpdir = tempfile.gettempdir()
        for f in os.listdir(tmpdir):
            if f.endswith(".flow"):
                os.remove(os.path.join(tmpdir, f))

    def local_interface_created(self):
        res = subprocess.check_output(["ip", "addr", "show", "lo"])
        return "lo:40" in res

    def create_attack(self, **kwargs):
        self.attack['args'] = kwargs
        if "sip" not in kwargs:
            self.attacker_ip = next(self.prefixv4)
            self.attack['args']['sip'] = self.attacker_ip
        else:
            self.attacker_ip = kwargs['sip']

        if "dip" in kwargs:
            if self.safe_mode:
                self.attack['args']['dip'] = next(self.prefixv4)
            else:
                self.attack['args']['dip'] = IPv4Address(self.attack['args']['dip'])

    def run(self, numflow):
        first_cat = None
        flow = self.flows.values()[0]
        if flow.dport in self.categories:
            first_cat = flow.dport
        elif flow.sport in self.categories:
            first_cat = flow.sport
        else:
            first_cat = 0

        self.last_cat = first_cat

        sw_cli = "s1"
        sw_host = "s2"
        sw_capt = "s3"
        ht_capt = "ids"
        lock = RLock()
        if self.mininet_mode:
            topo = GenTopo(sw_cli, sw_host, sw_capt, ht_capt)
            net = Mininet(topo)
            net_handler = NetworkHandler(net, lock)

            net_handler.run(self.output, self.subnet)
        else:
            if not self.local_interface_created():
                subprocess.call(["ifconfig", "lo:40", "172.16.0.0", "netmask", "255.255.0.0"])
            net_handler = LocalHandler()
            print "Starting capturing packet"
            sniffer = subprocess.Popen(["sudo", "tcpdump", "-i", "lo", "net", "172.16",
                                        "-w", "{}".format(self.output)])
        time.sleep(1)

        #cleaner = RepeatedTimer(10, net_handler.remove_done_host)

        i = 0
        waiting_time = 0
        suc_flow = 0

        thread_writting = []

        new_flow = 0

        for frame in xrange(len(self.dir_stats)):
            print "Starting frame number {}".format(frame)
            self.frame_index = frame
            next_frame_flow = self.get_next_frame_flow()
            frame_starting = time.time()
            frame_ending = frame_starting + self.frame_size
            if frame != 0:
                print "Redefining flow"
                flowseq = self.redefine_flows()
                assert len(self.flows) == len(flowseq)

            else:
                flowseq = self.flows.keys()

            if self.do_attack and frame == self.attack_frame:
                self.create_attack(net=self.subnet, size=30, nbr=1024,
                                   inter=0.150)
                #self.create_attack(spoof=unicode("10.0.0.1"), dport=2499,
                #                   dip=unicode("10.0.0.3"), sport=55434, inter=0.05) 
                res = net_handler.run_attacker(self.attack)
                if res:
                    print "Attacker IP: {}".format(self.attacker_ip)

            for i, fk in enumerate(flowseq):
                if numflow and i > numflow - 1:
                    break

                # The order of the flow (and the directio) can change from frame to frame
                if fk in self.flows:
                    flow = self.flows[fk]
                else:
                    flow = self.flows[fk.get_reverse()]
                before_waiting = time.time()
                last = False

                # Flow not in next frame
                if frame == len(self.dir_stats) - 1:
                    last = True
                else:
                    last = fk not in next_frame_flow

                if flow.first_frame < self.frame_index:
                    print "Continuing flow {}, last:{}".format(flow, last)
                else:
                    print "Trying to establish flow nbr:{}  {},last:{}".format((new_flow+1), flow, last)
                    new_flow += 1

                src_pipe, dst_pipe = self.create_flow_pipename(flow)
                res = net_handler.establish_conn_client_server(flow, self.pipelock[src_pipe],
                                                               self.pipelock[dst_pipe],
                                                               last)
                if res:
                    t_client, t_server = res
                    suc_flow += 1
                    print "Flow successfully established"
                    thread_writting.append(t_client)
                    thread_writting.append(t_server)
                else:
                    print "Failed to establish flow"
                time_to_establish = time.time() - before_waiting
                if i < len(self.flows) - 1:
                    interflowtime = (flowseq[i+1].first - flowseq[i].first).total_seconds()
                    tmp = interflowtime - time_to_establish
                    if tmp < 0:
                        tmp = 0
                    if tmp > 0.2 * self.frame_size:
                        tmp = 0.2 * self.frame_size

                    waiting_time = tmp
                    print "Waiting for %s" % waiting_time
                    time.sleep(waiting_time)

            print "Waiting next frame"
            cur = time.time()
            tmp = cur - frame_ending
            if tmp < 0:
                waiting_time = abs(0.2 * tmp)
            else:
                waiting_time = 0
            print "Waiting for %s" % waiting_time
            time.sleep(waiting_time)


        for thr in thread_writting:
            if thr.is_alive():
                thr.join()

        if args.debug and self.mininet_mode:
            CLI(net)

        net_handler.wait_termination()

        if self.mininet_mode:
            net_handler.stop(self.output)
        else:
            print "Stopping capture"
            #sniffer.terminate()
            time.sleep(1.5)
        self.export_mapping_ip()
        #cleaner.stop()


    def estimate_distribution(self, flow, pkt_dist, arr_dist, niter, clt=True,
                              estpkt=True, estarr=True):
        try:
            if clt:
                if estpkt:
                    flow.estim_pkt = DiscreteGen(util.get_pmf(pkt_dist))
                if estarr:
                    if len(arr_dist) > FlowHandler.MIN_SAMPLE_SIZE:
                        distribution, _ = self.compare_empirical_estim(arr_dist,
                                                                          niter)
                        flow.estim_arr = ContinuousGen(distribution)
                    else:
                        flow.estim_arr = DiscreteGen(util.get_pmf(arr_dist))

            else:
                if estpkt:
                    flow.in_estim_pkt = DiscreteGen(util.get_pmf(pkt_dist))
                if estarr:
                    if len(arr_dist) > FlowHandler.MIN_SAMPLE_SIZE:
                        distribution, _ = self.compare_empirical_estim(arr_dist,
                                                                          niter)
                        flow.in_estim_arr = ContinuousGen(distribution)
                    else:
                        flow.in_estim_arr = DiscreteGen(util.get_pmf(arr_dist))
        except TypeError:
            print flow
            pdb.set_trace()

    def compare_empirical_estim(self, data, niter):

        try:
            nb_sample = len(data)

            # List of the distribution represented as a tuple RV and weight
            # [[(gamma,1)], [(beta, 1)], ...]
            data_reshape = np.array(data).reshape(-1, 1)
            kernel_d = KernelDensity(bandwidth=0.1, kernel='gaussian')
            kernel_d.fit(data_reshape)
            return  [(kernel_d, 1)], "sci-kde"

        except ValueError:
            print data

    def apply_dist_from_name(self, name, data):

        if name == "gamma":
            gamma_shape, gamma_loc, gamma_scale = stats.gamma.fit(data)
            gamma_dist = stats.gamma(a=gamma_shape, scale=gamma_scale,
                                     loc=gamma_loc)
            return [(gamma_dist, 1)]
        elif name == "beta":
            beta_shape_a, beta_shape_b, beta_loc, beta_scale = stats.beta.fit(data)
            beta_dist = stats.beta(beta_shape_a, beta_shape_b, loc=beta_loc,
                                   scale=beta_scale)
            return [(beta_dist, 1)]
        elif name == "bimodal":
            gmm = GaussianMixture(n_components=2, covariance_type='spherical')
            gmm.fit(np.array(data).reshape(-1, 1))
            mu1 = gmm.means_[0, 0]
            mu2 = gmm.means_[1, 0]
            var1, var2 = gmm.covariances_
            wgt1, wgt2 = gmm.weights_

            norma_dist = stats.norm(mu1, var1)
            normb_dist = stats.norm(mu2, var2)

            return [(norma_dist, wgt1), (normb_dist, wgt2)]

        elif name == "KDE":
            kde = gaussian_kde(data)
            return [(kde, 1)]

        elif name == "sci-kde":
            kde = KernelDensity(data)
            return [(kde, 1)]

        else:
            raise ValueError("The {} is not a valid distribution".format(name))

    def _estimate_cluster(self, data_arr, data_pkt, name):
        resname = name
        if len(data_arr) > FlowHandler.MIN_SAMPLE_SIZE:
            if resname == "":
                dist, resname = self.compare_empirical_estim(data_arr,
                                                             FlowHandler.NB_ITER)
            else:
                dist = self.apply_dist_from_name(name, data_arr)
            gen_arr = ContinuousGen(dist)
        else:
            gen_arr = DiscreteGen(util.get_pmf(data_arr))

        gen_pkt = DiscreteGen(util.get_pmf(data_pkt))

        return resname, gen_arr, gen_pkt

    def estimate_cluster(self, clusters):

        for c in clusters:
            name = ""
            for i, flowkey in enumerate(c.flows):
                if flowkey in self.flows:
                    flow = self.flows[flowkey]

                elif flowkey.get_reverse() in self.flows:
                    flow = self.flows[flowkey.get_reverse()]
                else:
                    raise ValueError("The flow {} is does not exist".format(flowkey))

                if flowkey == flow.key:
                    name, gen_arr, gen_pkt = self._estimate_cluster(flow.arr_dist,
                                                                    flow.pkt_dist,
                                                                    name)
                    flow.estim_arr = gen_arr
                    flow.estim_pkt = gen_pkt

                elif flowkey == flow.key.get_reverse():
                    name, gen_arr, gen_pkt = self._estimate_cluster(flow.in_arr_dist,
                                                                    flow.in_pkt_dist,
                                                                    name)
                    flow.in_estim_arr = gen_arr
                    flow.in_estim_pkt = gen_pkt
                else:
                    continue


def test_flow_redefinition(config):

    handler = FlowHandler(config)
    target_flowkey = FlowKey(srcip=ip_address(unicode("10.0.0.1")),
                             dstip=ip_address(unicode("10.0.0.2")), sport=2499,
                             dport=55434, proto=6)

    sim = Simulator(target_flowkey, "flowstats.sim", "timeseries.sim")

    first_cat = None
    flow = handler.flows.values()[0]
    if flow.dport in handler.categories:
        first_cat = flow.dport
    elif flow.sport in handler.categories:
        first_cat = flow.sport
    else:
        first_cat = 0

    handler.last_cat = first_cat

    i = 0
    waiting_time = 0
    new_flow = 0

    for frame in xrange(len(handler.dir_stats)):
        print "Starting frame number {}".format(frame)
        handler.frame_index = frame
        next_frame_flow = handler.get_next_frame_flow()
        frame_starting = time.time()
        frame_ending = frame_starting + handler.frame_size
        if frame != 0:
            print "Redefining flow"
            flowseq = handler.redefine_flows()
            assert len(handler.flows) == len(flowseq)

        else:
            flowseq = handler.flows.keys()

        for i, fk in enumerate(flowseq):
            # The order of the flow (and the directio) can change from frame to frame
            if fk in handler.flows:
                flow = handler.flows[fk]
            else:
                flow = handler.flows[fk.get_reverse()]
            before_waiting = time.time()
            last = False

            # Flow not in next frame
            if frame == len(handler.dir_stats) - 1:
                last = True
            else:
                last = fk not in next_frame_flow

            if flow.first_frame < handler.frame_index:
                print "Continuing flow {}, last:{}".format(flow, last)
            else:
                print "Trying to establish flow nbr:{}  {},last:{}".format((new_flow+1), flow, last)
                new_flow += 1

            sim.write_flow(flow)

            time_to_establish = time.time() - before_waiting
            if i < len(handler.flows) - 1:
                interflowtime = (flowseq[i+1].first - flowseq[i].first).total_seconds()
                tmp = interflowtime - time_to_establish
                if tmp < 0:
                    tmp = 0
                if tmp > 0.75 * handler.frame_size:
                    tmp = 0.75 * handler.frame_size

                waiting_time = tmp
                print "Waiting for %s" % waiting_time

        print "Waiting next frame"
        cur = time.time()
        tmp = cur - frame_ending
        if tmp < 0:
            waiting_time = abs(0.25 * tmp)
        else:
            waiting_time = 0
        print "Waiting for %s" % waiting_time
    handler.export_mapping_ip()
    sim.stop()

def test_flow_time_slice(config):
    try:
        FlowHandler.clean_tmp()
        handler = FlowHandler(config, mode="mininet", saveflow=None,
                              loadflow=None, savedist=None, loaddist=None)
        for frame in xrange(len(handler.dir_stats)):
            print "Starting frame number {}".format(frame)
            handler.frame_index = frame
            flow_next_frame = handler.get_next_frame_flow()
            if frame != 0:
                handler.redefine_flows()

            flowseq = handler.flows.keys()
            print "Nbr flow in frame {}".format(len(handler.flows))
            for _, fk in enumerate(flowseq):
                flow = handler.flows[fk]

                if frame == len(handler.dir_stats) - 1:
                    last = True
                else:
                    last = fk not in flow_next_frame
                if flow.first_frame < handler.frame_index:
                    print "Cont: {}, last:{}, src:{}, dst:{}".format(flow, last,
                                                                     flow.nb_pkt,
                                                                     flow.in_nb_pkt)
                else:
                    print "Establ: {}, last:{}, src:{}, dst:{}".format(flow,
                                                                       last,
                                                                       flow.nb_pkt,
                                                                       flow.in_nb_pkt)
    finally:
        pass

def test_attack(config):
    try:
        FlowHandler.clean_tmp()
        handler = FlowHandler(config, mode="mininet", saveflow=None,
                              loadflow=None, savedist=None, loaddist=None)
        for frame in xrange(len(handler.dir_stats)):
            print "Starting frame number {}".format(frame)
            handler.frame_index = frame
            flow_next_frame = handler.get_next_frame_flow()
            if frame != 0:
                handler.redefine_flows()

            if frame == 2:
                fullname = os.path.join(handler.attack["dir"],
                                        handler.attack["name"])
                handler.create_attack(dip="10.0.0.1", dport=2499,
                                      npkt=1000, inter=0.001)
                cmd = "{} {} ".format(handler.attack["cmd"], fullname)
                for k, v in handler.attack["args"].items():
                    cmd += "--{} {} ".format(str(k), str(v))
                print cmd

            flowseq = handler.flows.keys()
            print "Nbr flow in frame {}".format(len(handler.flows))
            for _, fk in enumerate(flowseq):
                flow = handler.flows[fk]
                
                if frame == len(handler.dir_stats) - 1:
                    last = True
                else:
                    last = fk not in flow_next_frame
                if flow.first_frame < handler.frame_index:
                    print "Cont: {}, last:{}, src:{}, dst:{}".format(flow, last,
                                                                     flow.nb_pkt,
                                                                     flow.in_nb_pkt)
                else:
                    print "Establ: {}, last:{}, src:{}, dst:{}".format(flow,
                                                                       last,
                                                                       flow.nb_pkt,
                                                                       flow.in_nb_pkt)
    finally:
        pass

def main(config, numflow=None, mode="mininet", read="bin", saveflow=None, loadflow=None,
         savedist=None, loaddist=None):
    try:
        FlowHandler.clean_tmp()
        handler = FlowHandler(config, mode, read, saveflow, loadflow, savedist, loaddist)
        handler.run(numflow)
    finally:
        sh('pkill -f "python -u server.py"')
        sh('pkill -f "python -u client.py"')
        if mode == "mininet":
            cleanup()

if __name__ == "__main__":
    main(args.config, args.numflow, args.mode, args.read,
         args.saveflow, args.loadflow, args.savedist,
         args.loaddist)
    #test_flow_time_slice(args.config)
    #test_attack(args.config)
    #test_flow_redefinition(args.config)
