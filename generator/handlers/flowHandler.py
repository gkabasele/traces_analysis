#!/usr/bin/python
import struct
import sys
import os
import argparse
import time
import bisect
import yaml
import numpy as np
import math
import matplotlib as mpl
import scipy as sp
import scipy.stats as stats
import matplotlib.pyplot as plt
import random as rm
import util
from binascii import hexlify
from flows import Flow
from flows import FlowKey
from flows import FlowCategory
from ipaddress import IPv4Address
from ipaddress import ip_network
from networkHandler import NetworkHandler
from networkHandler import GenTopo
from mininet.net import Mininet
from mininet.util import dumpNodeConnections
from mininet.cli import CLI
from threading import Lock
from datetime import datetime
from datetime import timedelta
from sklearn.mixture import GaussianMixture
from sklearn.neighbors import KernelDensity


parser = argparse.ArgumentParser()
parser.add_argument("--dur", type=int, dest="duration", action="store")
parser.add_argument("--conf", type=str, dest="config", action="store")
parser.add_argument("--debug", type=str, dest="debug", action="store")

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

    """
        This is the main class coordinating the creation/deletion of flows
    """

    def __init__(self, config):

        with open(config, 'r') as stream:
            try:
                conf = yaml.load(stream)
            except yaml.YAMLError as exc:
                print exc
                return

            filename = conf['input']
            appli = conf['application']
            self.output = conf['output']
            self.subnet = conf['prefixv4']
            self.prefixv4 = ip_network(unicode(conf['prefixv4'])).hosts()
            self.categories = {}
            # Keep category distribution 
            self.category_dist = {}      
            self.create_categorie(appli)
            self.mapping_address = {}

            self.index = 0
            self.flowseq = []
            self.flows = self.retrieve_flows(filename)

            self.compute_flow_corr()

            # Last category that was spawn
            self.last_cat = None

            # Last flow that were spawn
            self.last_flow = None

            
            

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
        key_out = None
        key_in = None
        if sport in self.categories:
            key_in = FlowKey(dstip, srcip, dport, sport, proto, None, sport)
            key_out = FlowKey(srcip, dstip, sport, dport, proto, first, sport)
        elif dport in self.categories:
            key_in = FlowKey(srcip, dstip, sport, dport, proto, first, dport)
            key_out = FlowKey(dstip, srcip, dport, sport, proto, None, dport)
        
        
        
        return (key_out, key_in)

    def retrieve_flows(self, filename):
        flows = {}
        with open(filename, "rb") as f:
            filesize = os.path.getsize(filename)
            while self.index < filesize:
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

                
                srv_flow, clt_flow = self.get_flow_key(srcip, dstip, sport, dport,
                                                       proto, first)
                
                if srv_flow is None and clt_flow is None:

                    clt_flow  = FlowKey(srcip, dstip, sport, dport, proto, first, 0) 
                    srv_flow = FlowKey(dstip, srcip, dport, sport, proto, None, 0) 

                flow_cat = self.category_dist[clt_flow.cat]
                if not (clt_flow in flows or srv_flow in flows):
                    if clt_flow.first is not None:
                        flow = Flow(clt_flow, duration, size, nb_pkt, pkt_dist,
                                    arr_dist)
                        flows[clt_flow] = flow
                        self.flowseq.append(clt_flow)
                    elif srv_flow.first is not None:
                        flow = Flow(srv_flow, duration, size, nb_pkt, pkt_dist,
                                    arr_dist)
                        flows[srv_flow] = flow
                        self.flowseq.append(srv_flow)
                    else:
                        raise ValueError("Invalid time for flow first appearance")

                elif clt_flow in flows:
                    # If source ip are different, then its a server flow of an
                    # already known flow
                    if srcip != clt_flow.srcip:
                        flow = flows[clt_flow]
                        flow.set_reverse_stats(duration, size, nb_pkt, pkt_dist,
                                               arr_dist)
                        flow_cat.add_flow_client(flow.size, flow.nb_pkt,
                                                 flow.dur)
                        flow_cat.add_flow_server(size, nb_pkt, duration)
                elif srv_flow in flows:
                    if srcip != srv_flow.srcip:
                        flow = flows[srv_flow]
                        flow.set_reverse_stats(duration, size, nb_pkt, pkt_dist,
                                               arr_dist)
                        flow_cat.add_flow_client(size, nb_pkt, duration)
                        flow_cat.add_flow_server(flow.size, flow.nb_pkt,
                                                 flow.dur)
        self.index = 0
        return flows

    def create_categorie(self, appli):
        for k in appli:
            # random port following an application port
            self.categories[int(k)] = {}
            self.category_dist[int(k)] = FlowCategory(int(k))
        self.categories[0] = {}
        self.category_dist[0] = FlowCategory(0)

    def compute_flow_corr(self):
        i = 0
        randport = 0
        #FIXME Kind of disgusting
        while i < len(self.flowseq) - 1:
            cur_dport = (self.flowseq[i].dport)
            cur_sport = (self.flowseq[i].sport)
            next_dport = (self.flowseq[i+1].dport)
            next_sport = (self.flowseq[i+1].sport)

            if next_dport not in self.categories:
                next_dport = 0

            if next_sport not in self.categories:
                next_sport = 0


            if cur_dport in self.categories:
                if next_dport in self.categories:
                    if next_dport in self.categories[cur_dport]:
                        self.categories[cur_dport][next_dport] += 1
                    else:
                        self.categories[cur_dport][next_dport] = 1


                elif next_sport in self.categories:
                    if next_sport in self.categories[cur_dport]:
                        self.categories[cur_dport][next_sport] += 1
                    else:
                        self.categories[cur_dport][next_sport] = 1

                else:
                    if randport in self.categories[cur_dport]:
                        self.categories[cur_dport][randport] += 1
                    else:
                        self.categories[cur_dport][randport] = 1

            if cur_sport in self.categories:
                if next_dport in self.categories:
                    if next_dport in self.categories[cur_sport]:
                        self.categories[cur_sport][next_dport] += 1
                    else:
                        self.categories[cur_sport][next_dport] = 1
                elif next_sport in self.categories:
                    if next_sport in self.categories[cur_sport]:
                        self.categories[cur_sport][next_dport] += 1
                    else:
                        self.categories[cur_sport][next_dport] = 1

                else:
                    if randport in self.categories[cur_sport]:
                        self.categories[cur_sport][randport] += 1
                    else:
                        self.categories[cur_sport][randport] = 1

            else:
                if next_dport in self.categories:
                    if next_dport in self.categories[randport]:
                        self.categories[randport][next_dport] += 1
                    else:
                        self.categories[randport][next_dport] = 1
                elif next_sport in self.categories:
                    if next_sport in self.categories[randport]:
                        self.categories[randport][next_sport] += 1
                    else:
                        self.categories[randport][next_dport] = 1
                else:
                    if randport in self.categories[randport]:
                        self.categories[randport][randport] += 1
                    else:
                        self.categories[randport][randport] = 1

            i += 1

        for k in self.categories:
            total = sum(self.categories[k].values())
            for c in self.categories[k]:
                val = self.categories[k][c]
                self.categories[k][c] = val/float(total)

    def get_next_cat(self):
        if self.last_cat in self.categories:
            poss = self.categories[self.last_cat]
            cat = poss.keys()
            prob = poss.values()
            new_cat = np.random.choice(cat, replace=True, p=prob)
            if new_cat != 0:
                self.last_cat = new_cat
                return new_cat
            else:
                self.last_cat = 0
                return rm.randint(1024, 65535)

    def change_cat(self, flow):
        if flow.dport in self.categories:
            self.last_cat = flow.dport
        elif flow.sport in self.categories:
            self.last_cat = flow.sport
        else:
            self.last_cat = 0

    def get_flow_from_cat(self, cat):
        return filter(lambda x: x.cat == cat, self.flows.keys())


    def connect_to_network(self, ip, port):
        # Connect to network manager to create new  host
        pass

    """
        Create an host with ip and port open
    """
    def open_service(self, ip, port):
        pass

    def init_flow(self, flow):
        pass

    def close_flow(self, flow):
        pass

    def run(self, duration):
        flow = self.flowseq[0]
        first_cat = None
        if flow.dport in self.categories:
            first_cat = flow.dport
        elif flow.sport in self.categories:
            first_cat = flow.sport
        else:
            first_cat = 0

        self.last_cat = first_cat


        sw_cli = "s1"
        sw_host = "s2"
        lock = Lock()
        topo = GenTopo(sw_cli, sw_host)
        net = Mininet(topo)
        net_handler = NetworkHandler(net, lock)

        cap_cli = "cli.pcap"
        cap_srv = "srv.pcap"

        net_handler.run(cap_cli, cap_srv, self.subnet)

        time.sleep(1)

        #cleaner = RepeatedTimer(10, net_handler.remove_done_host)

        start_time = time.time()
        elapsed_time = 0
        i = 0
        waiting_time = 0
        while elapsed_time < duration:
            if i < len(self.flowseq)-1:
                f = self.flowseq[i]
                flow = self.flows[f]
                net_handler.establish_conn_client_server(flow)
                waiting_time = (self.flowseq[i+1].first -
                                self.flowseq[i].first).total_seconds()
                i += 1
            elif i == len(self.flowseq)-1:
                i += 1
            else:
                pass
            time.sleep(waiting_time)
            elapsed_time = time.time() - start_time
        #dumpNodeConnections(net.hosts)

        if args.debug:
            CLI(net)

        net_handler.stop(self.output, cap_cli, cap_srv)
        #cleaner.stop()

    def display_flow_dist(self, flow_num):
        f = self.flowseq[flow_num]
        flow = self.flows[f]
        pkt_dist = util.get_pmf(flow.pkt_dist)

        print "Nbr packet: {}, Nbr Interarrival: {}".format(len(flow.pkt_dist),
                                                            len(flow.arr_dist))

        fig = plt.figure(figsize=(30, 30))
        ax = fig.add_subplot(1, 2, 1)
        x = sorted(pkt_dist.keys())
        y = [pkt_dist[i] for i in x]


        pkt_gen = np.random.choice(x, len(pkt_dist), p=y)
        pkt_dist_gen = util.get_pmf(pkt_gen)
        x_gen = sorted(pkt_dist_gen.keys())
        y_gen = [pkt_dist_gen[i] for i in x_gen]


        ax.bar(x, y,width=4)
        ax.bar(x_gen, y_gen, color="red", width=4,alpha=0.5)
        ax.set_xlabel("size(B)")
        ax.set_ylabel("Frequency")
        ax.set_title("{}:{}<->{}:{}".format(flow.srcip, flow.sport, flow.dstip,
                                            flow.dport))
        '''
        #std = np.std(flow.arr_dist)
        #mean = np.mean(flow.arr_dist)
        #alpha = (mean/std)**2
        #beta =  std**2/mean

        #accepted, rejected = util.estimate_distribution(flow.arr_dist, nb_iter,
        #                                                [1, 2], [0.05,5])
        #print "Alpha: {} Beta: {}".format(alpha, beta)
        #print "Accepted: {}, Rejected: {}".format(len(accepted), len(rejected))
        #print accepted [-50:]
        #alpha = np.mean([x[0] for x in accepted[:nb_iter/2]])
        #beta = np.mean([x[1] for x in accepted[:nb_iter/2]])
        #approx = stats.gamma(a=alpha, scale=beta).rvs(len(flow.arr_dist))
        '''
        gamma_shape, gamma_loc, gamma_scale = stats.gamma.fit(flow.arr_dist)
        approx = stats.gamma(a=gamma_shape, scale=gamma_scale,
                             loc=gamma_loc).rvs(len(flow.arr_dist))

        beta_shape_a, beta_shape_b, beta_loc, beta_scale = stats.beta.fit(flow.arr_dist)
        approx_b = stats.beta(beta_shape_a, beta_shape_b, loc=beta_loc,
                              scale=beta_scale).rvs(len(flow.arr_dist))

        gmm = GaussianMixture(n_components=2, covariance_type='spherical')
        gmm.fit(np.array(flow.arr_dist).reshape(-1, 1))

        mu1 = gmm.means_[0, 0]
        mu2 = gmm.means_[1, 0] 
        var1, var2 = gmm.covariances_
        wgt1, wgt2 = gmm.weights_

        print "Weight 1: {}, Weight 2: {}".format(wgt1, wgt2)
        approx_c = np.concatenate((
            stats.norm(mu1, var1).rvs(int(len(flow.arr_dist) * wgt1)),
            stats.norm(mu2, var2).rvs(int(len(flow.arr_dist) * wgt2))))

        print "Diff Gamma: {}".format(abs(np.sum(approx) - np.sum(flow.arr_dist)))
        print "Diff Beta: {}".format(abs(np.sum(approx_b) - np.sum(flow.arr_dist)))
        print "Diff BiMod: {}".format(abs(np.sum(approx_c) -np.sum(flow.arr_dist)))
                                          
        ax = fig.add_subplot(1, 2, 2)
        n, bins, patches = ax.hist(flow.arr_dist, bins=200, alpha=0.5, density=True)
        ax.hist(approx, bins, color ="red", alpha=0.5, density=True)
        ax.hist(approx_b, bins, color ="green", alpha=0.5, density=True)
        ax.hist(approx_c, bins, color="purple", alpha=0.5, density=True)
        ax.set_xlabel("inter-arrival (ms)")
        ax.set_ylabel("Frequency")
        ax.set_title("{}:{}<->{}:{}".format(flow.srcip, flow.sport, flow.dstip,
                                            flow.dport))
        plt.show()

    def display_cat_dist(self, cat):
        flow_cat = self.category_dist[cat]
        fig = plt.figure(figsize=(30, 30))

        clt_size = [x/float(100) for x in flow_cat.clt_size]
        srv_size = [x/float(100) for x in flow_cat.srv_size]

        ax = fig.add_subplot(2, 3, 1)

        ax.hist(clt_size, bins=100)
        ax.set_xlabel("size (kB)")
        ax.set_ylabel("Frequency")
        ax.set_title("Category {} Client size distribution".format(cat))

        ax = fig.add_subplot(2, 3, 4)
        ax.hist(srv_size, bins=100)
        ax.set_xlabel("size (kB)")
        ax.set_ylabel("Frequency")
        ax.set_title("Category {} Server size distribution".format(cat)) 

        ax = fig.add_subplot(2, 3, 2)
        ax.hist(flow_cat.clt_nb_pkt, bins=100)
        ax.set_xlabel("Nbr Pkt")
        ax.set_ylabel("Frequency")
        ax.set_title("Client Nbr Pkt distribution")

        ax = fig.add_subplot(2, 3, 5)
        ax.hist(flow_cat.srv_nb_pkt, bins=100)
        ax.set_xlabel("Nbr Pkt")
        ax.set_ylabel("Frequency")
        ax.set_title("Server Nbr Pkt distribution")

        ax = fig.add_subplot(2, 3, 3)
        ax.hist(flow_cat.clt_dur, bins=100)
        ax.set_xlabel("Duration (ms)")
        ax.set_ylabel("Frequency")
        ax.set_title("Client duration distribution")

        ax = fig.add_subplot(2, 3, 6)
        ax.hist(flow_cat.srv_dur, bins=100)
        ax.set_xlabel("Duration (ms)")
        ax.set_ylabel("Frequency")
        ax.set_title("Server duration distribution")

        plt.show()


def main(config, duration):

    handler = FlowHandler(config)
    #handler.run(duration)
    handler.display_flow_dist(2)
    #handler.display_cat_dist(443)
    #print handler.category_dist[50000]

if __name__ == "__main__":
    main(args.config, args.duration)
