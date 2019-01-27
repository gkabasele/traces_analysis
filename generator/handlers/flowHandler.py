#!/usr/bin/python
import struct
import sys
import os
import argparse
import time
import traceback
import random as rm
import pickle
import pprint
import pdb
from threading import Lock
from datetime import datetime
from datetime import timedelta
from ipaddress import IPv4Address, ip_network
from collections import OrderedDict

import numpy as np
import matplotlib.pyplot as plt
import scipy.stats as stats
from scipy.stats.kde import gaussian_kde
from sklearn.mixture import GaussianMixture
from sklearn.neighbors import KernelDensity
from sklearn.metrics import mean_squared_error
import yaml
from mininet.net import Mininet
from mininet.util import dumpNodeConnections
from mininet.cli import CLI

import util
import clustering
from flows import Flow, FlowKey, FlowCategory
from flows import DiscreteGen, ContinuousGen
from networkHandler import NetworkHandler, GenTopo

parser = argparse.ArgumentParser()
parser.add_argument("--dur", type=int, dest="duration", action="store")
parser.add_argument("--conf", type=str, dest="config", action="store")
parser.add_argument("--debug", type=str, dest="debug", action="store")
parser.add_argument("--saveflow")
parser.add_argument("--loadflow")
parser.add_argument("--savedist")
parser.add_argument("--loaddist")

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

    def __init__(self, config, saveflow=None, loadflow=None, 
                 savedist=None, loaddist=None):

        with open(config, 'r') as stream:
            try:
                conf = yaml.load(stream)

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
                '''
                if loaddist is not None:
                    input_pck = conf['input_dist']
                    with open(input_pck, 'rb') as fh:
                        self.distances = pickle.load(fh)
                elif savedist is not None:
                    output_pck = conf['output_dist']
                    self.distances = self.compute_flows_distances(util.distance_ks, output_pck)

                else:
                    self.distances = self.compute_flows_distances(util.distance_ks)
                '''
                self.compute_flow_corr()

                # Last category that was spawn
                self.last_cat = None

                # Last flow that were spawn
                self.last_flow = None

            except yaml.YAMLError as exc:
                print exc
                return
            except AssertionError:
                print "Cannot load and save at the same time"


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

    def retrieve_flows(self, filename, output_pck=None):
        flows = OrderedDict()
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

                    clt_flow = FlowKey(srcip, dstip, sport, dport, proto, first, 0)
                    srv_flow = FlowKey(dstip, srcip, dport, sport, proto, None, 0)

                flow_cat = self.category_dist[clt_flow.cat]
                if not (clt_flow in flows or srv_flow in flows):
                    if clt_flow.first is not None:
                        flow = Flow(clt_flow, duration, size, nb_pkt, pkt_dist,
                                    arr_dist)
                        flows[clt_flow] = flow
                        self.estimate_distribution(flow, FlowHandler.NB_ITER)

                    elif srv_flow.first is not None:
                        flow = Flow(srv_flow, duration, size, nb_pkt, pkt_dist,
                                    arr_dist)
                        flows[srv_flow] = flow
                        self.estimate_distribution(flow, FlowHandler.NB_ITER)
                    else:
                        raise ValueError("Invalid time for flow first appearance")

                elif clt_flow in flows:
                    # If source ip are different, then its a server flow of an
                    # already known flow
                    if srcip != clt_flow.srcip:
                        flow = flows[clt_flow]
                        flow.set_reverse_stats(duration, size, nb_pkt, pkt_dist,
                                               arr_dist)
                        self.estimate_distribution(flow, FlowHandler.NB_ITER,
                                                  clt=False)
                        flow_cat.add_flow_client(flow.size, flow.nb_pkt,
                                                 flow.dur)
                        flow_cat.add_flow_server(size, nb_pkt, duration)
                elif srv_flow in flows:
                    if srcip != srv_flow.srcip:
                        flow = flows[srv_flow]
                        flow.set_reverse_stats(duration, size, nb_pkt, pkt_dist,
                                               arr_dist)
                        self.estimate_distribution(flow, FlowHandler.NB_ITER,
                                                   clt=False)
                        flow_cat.add_flow_client(size, nb_pkt, duration)
                        flow_cat.add_flow_server(flow.size, flow.nb_pkt,
                                                 flow.dur)

                assert flow.estim_arr is not None and flow.estim_pkt is not None

        self.index = 0
        if output_pck is not None:
            with open(output_pck, 'wb') as fh:
                pickle.dump(flows, fh)

        return flows

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

            #if flow.key not in norms:
            #    norms[flow.key] = util.normalize_data(flow.arr_dist)

            if hasrev:
                revkey = flow.get_reverse()
                distances[revkey] = OrderedDict()

                #if revkey not in norms:
                #    norms[revkey] = util.normalize_data(flow.in_arr_dist)

                # computing distance with reverse flow
                #d = fun(norms[flow.key], norms[revkey])
                d = fun(flow.arr_dist, flow.in_arr_dist)
                distances[flow.key][revkey] = d

            for j in range(i+1, len(flowskey)):
                nextflow = self.flows[flowskey[j]]
                nexthasrev = nextflow.in_arr_dist is not None

                #if nextflow.key not in norms:
                #    norms[nextflow.key] = util.normalize_data(nextflow.arr_dist)

                #d = fun(norms[flow.key], norms[nextflow.key])
                d = fun(flow.arr_dist, nextflow.arr_dist)
                distances[flow.key][nextflow.key] = d

                if nexthasrev:
                    nextrevkey = nextflow.get_reverse()

                    #if nextrevkey not in norms:
                    #    norms[nextrevkey] = util.normalize_data(nextflow.in_arr_dist)

                    #d = fun(norms[flow.key], norms[nextrevkey])
                    d = fun(flow.arr_dist, nextflow.in_arr_dist)
                    distances[flow.key][nextrevkey] = d

                    if hasrev:
                        #d = fun(norms[revkey], norms[nextrevkey])
                        d = fun(flow.in_arr_dist, nextflow.in_arr_dist)
                        distances[revkey][nextrevkey] = d

                if hasrev:
                    #d = fun(norms[revkey], norms[nextflow.key])
                    d = fun(flow.in_arr_dist, nextflow.arr_dist)
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

    def _add_to_cat(self, cur_port, next_port):

        if next_port in self.categories[cur_port]:
            self.categories[cur_port][next_port] += 1
        else:
            self.categories[cur_port][next_port] = 1

    def compute_flow_corr(self):
        i = 0
        randport = 0
        flowseq = self.flows.keys()
        while i < len(flowseq) - 1:
            cur_dport = flowseq[i].dport
            cur_sport = flowseq[i].sport
            next_dport = flowseq[i+1].dport
            next_sport = flowseq[i+1].sport

            if next_dport not in self.categories:
                next_dport = 0

            if next_sport not in self.categories:
                next_sport = 0

            if cur_dport in self.categories:
                port = self._next_port_in_cat(next_sport, next_dport, randport)
                self._add_to_cat(cur_dport, port)

            elif cur_sport in self.categories:
                port = self._next_port_in_cat(next_sport, next_dport, randport)
                self._add_to_cat(cur_sport, port)

            else:
                port = self._next_port_in_cat(next_sport, next_dport, randport)
                self._add_to_cat(randport, port)

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
        flowseq = self.flows.keys()
        flow = flowseq[0]
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
            if i < len(flowseq)-1:
                f = flowseq[i]
                flow = self.flows[f]
                net_handler.establish_conn_client_server(flow)
                waiting_time = (flowseq[i+1].first -
                                flowseq[i].first).total_seconds()
                i += 1
            elif i == len(flowseq)-1:
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

    def estimate_distribution(self, flow, niter, clt=True):
        try:
            if clt:
                flow.estim_pkt = DiscreteGen(util.get_pmf(flow.pkt_dist))
                if len(flow.arr_dist) > FlowHandler.MIN_SAMPLE_SIZE:
                    distribution, name = self.compare_empirical_estim(flow.arr_dist,
                                                                      niter)
                    flow.estim_arr = ContinuousGen(distribution)
                else:
                    flow.estim_arr = DiscreteGen(util.get_pmf(flow.arr_dist))

            else:
                flow.in_estim_pkt = DiscreteGen(util.get_pmf(flow.in_pkt_dist))

                if len(flow.in_arr_dist) > FlowHandler.MIN_SAMPLE_SIZE:
                    distribution, name = self.compare_empirical_estim(flow.in_arr_dist,
                                                                      niter)
                    flow.in_estim_arr = ContinuousGen(distribution)
                else:
                    flow.in_estim_arr = DiscreteGen(util.get_pmf(flow.in_arr_dist))
        except TypeError:
            print flow
            pdb.set_trace()

    def compare_empirical_estim(self, data, niter):

        try:
            nb_sample = len(data)

            # List of the distribution represented as a tuple RV and weight
            # [[(gamma,1)], [(beta, 1)], ...]
            distribution_name = []
            distributions = []

            gamma_shape, gamma_loc, gamma_scale = stats.gamma.fit(data)
            gamma_dist = stats.gamma(a=gamma_shape, scale=gamma_scale,
                                     loc=gamma_loc)
            distribution_name.append("gamma")
            distributions.append([(gamma_dist, 1)])

            beta_shape_a, beta_shape_b, beta_loc, beta_scale = stats.beta.fit(data)
            beta_dist = stats.beta(beta_shape_a, beta_shape_b, loc=beta_loc,
                                   scale=beta_scale)
            distribution_name.append("beta")
            distributions.append([(beta_dist, 1)])

            gmm = GaussianMixture(n_components=2, covariance_type='spherical')
            gmm.fit(np.array(data).reshape(-1, 1))
            mu1 = gmm.means_[0, 0]
            mu2 = gmm.means_[1, 0]
            var1, var2 = gmm.covariances_
            wgt1, wgt2 = gmm.weights_

            norma_dist = stats.norm(mu1, var1)
            normb_dist = stats.norm(mu2, var2)

            distribution_name.append("bimodal")
            distributions.append([(norma_dist, wgt1), (normb_dist, wgt2)])

            kde = gaussian_kde(data)
            distribution_name.append("KDE")
            distributions.append([(kde, 1)])

            s = None
            index = None
            for i, dist in enumerate(distributions):
                ks_d = 0
                for j in xrange(niter):
                    sample = []
                    for rv in dist:
                        d, weight = rv
                        gensize = int(nb_sample * weight)
                        if isinstance(d, stats.gaussian_kde):
                            gendata = d.resample(size=gensize).reshape((gensize,))
                        else:
                            gendata = d.rvs(gensize)

                        sample = np.concatenate((
                            sample,
                            gendata))
                    diff = abs(nb_sample - len(sample))
                    # if some sample are missing
                    if diff != 0:
                        r = 0
                        for k in xrange(diff):
                            d, weight = dist[r]
                            r = (r + 1)% len(dist)
                            if isinstance(d, stats.gaussian_kde):
                                gendata = d.resample(size=1).reshape((1,))
                            else:
                                gendata = d.rvs(1)
                            sample = np.concatenate((
                                sample,
                                gendata))

                    ks_d += util.distance_ks(data, sample)

                tmp = ks_d/float(niter)

                if s is None or tmp < s:
                    s = tmp
                    index = i

            return  distributions[index], distribution_name[index]

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
                    pdb.set_trace()

                elif flowkey == flow.key.get_reverse():
                    name, gen_arr, gen_pkt = self._estimate_cluster(flow.in_arr_dist,
                                                                    flow.in_pkt_dist,
                                                                    name)
                    flow.in_estim_arr = gen_arr
                    flow.in_estim_pkt = gen_pkt
                else:
                    continue

    def plot_flow_dist(self, flow_id):

        if type(flow_id) is int:
            f = self.flows.keys()[flow_id]
            flow = self.flows[f]
        else:
            flow = self.flows[flow_id]

        fig = plt.figure(figsize=(15, 15))
        ax = fig.add_subplot(1, 2, 1)

        nb_sample = len(flow.arr_dist)
        n, bins, patches = ax.hist(flow.arr_dist, bins=200, density=True,
                                    label="Data")

        approx = flow.generate_client_arrs(nb_sample)

        kde = KernelDensity(bandwidth=1.0, kernel='gaussian')
        kde.fit(np.array(flow.arr_dist).reshape(-1,1))

        approx_b = kde.sample(nb_sample)

        ax.hist(approx, bins, color="red", alpha=0.5, density=True,
                label="Gen")

        ax.hist(approx_b, bins, color="green", alpha=0.5, density=True,
                label="Gen KDE")

        ax.set_xlabel("inter-arrival (ms)")
        ax.set_ylabel("Frequency")

        ax = fig.add_subplot(1, 2, 2)
        nb_sample = len(flow.in_arr_dist)
        n, bins, patches = ax.hist(flow.in_arr_dist, bins=200, density=True,
                                   label="Data")
        approx = flow.generate_server_arrs(nb_sample)
        kde = KernelDensity(bandwidth=1.0, kernel='gaussian')
        kde.fit(np.array(flow.in_arr_dist).reshape(-1, 1))

        approx_b = kde.sample(nb_sample)
        ax.hist(approx, bins, color="red", alpha=0.5, density=True,
                label="Gen")
        ax.hist(approx_b, bins, color="green", alpha=0.5, density=True,
                label="Gen KDE")
        ax.set_xlabel("inter-arrival (ms)")
        ax.set_ylabel("Frequency")

        ax.legend()
        plt.show()


    def display_flow_dist(self, flow_num):
        f = self.flows.keys()[flow_num]
        flow = self.flows[f]
        fig = plt.figure(figsize=(30, 30))
        ax = fig.add_subplot(1, 1, 1)
        nb_sample = len(flow.arr_dist)
        n, bins, patches = ax.hist(flow.arr_dist, bins=200, density=True,
                                   label='Data')

        gamma_shape, gamma_loc, gamma_scale = stats.gamma.fit(flow.arr_dist)
        approx = stats.gamma(a=gamma_shape, scale=gamma_scale,
                             loc=gamma_loc).rvs(nb_sample)

        beta_shape_a, beta_shape_b, beta_loc, beta_scale = stats.beta.fit(flow.arr_dist)
        approx_b = stats.beta(beta_shape_a, beta_shape_b, loc=beta_loc,
                              scale=beta_scale).rvs(nb_sample)

        gmm = GaussianMixture(n_components=2, covariance_type='spherical')
        gmm.fit(np.array(flow.arr_dist).reshape(-1, 1))

        max_arr = max(flow.arr_dist)
        min_arr = min(flow.arr_dist)
        x_val = np.linspace(min_arr, max_arr, 200)
        kde_pdf = gaussian_kde(flow.arr_dist)
        kde_est = kde_pdf.evaluate(x_val)

        approx_d = kde_pdf.resample(size=nb_sample).reshape((nb_sample,))

        mu1 = gmm.means_[0, 0]
        mu2 = gmm.means_[1, 0]
        var1, var2 = gmm.covariances_
        wgt1, wgt2 = gmm.weights_

        approx_c = np.concatenate((
            stats.norm(mu1, var1).rvs(int(nb_sample * wgt1)),
            stats.norm(mu2, var2).rvs(int(nb_sample * wgt2))))

        print "Diff Gamma: {}".format(abs(np.sum(approx) - np.sum(flow.arr_dist)))
        print "Diff Beta: {}".format(abs(np.sum(approx_b) - np.sum(flow.arr_dist)))
        print "Diff BiMod: {}".format(abs(np.sum(approx_c) -np.sum(flow.arr_dist)))
        print "Diff KDE: {}".format(abs(np.sum(approx_d) -np.sum(flow.arr_dist)))

        ax.plot(x_val, kde_est, color="gray", alpha=1, label="KDE")
        ax.hist(approx, bins, color ="red", alpha=0.5, density=True,
                label="Gamma")
        ax.hist(approx_b, bins, color ="green", alpha=0.5, density=True,
                label="Beta")
        ax.hist(approx_c, bins, color="purple", alpha=0.5, density=True,
                label="BiModal")

        ax.hist(approx_d, bins, color="orange", alpha=0.5, density=True,
                label="KDE Est")
        ax.set_xlabel("inter-arrival (ms)")
        ax.set_ylabel("Frequency")
        ax.set_title("{}:{}<->{}:{}".format(flow.srcip, flow.sport, flow.dstip,
                                            flow.dport))

        print "Same: {}".format(stats.ks_2samp(flow.arr_dist, flow.arr_dist))
        print "Gamma: {}".format(stats.ks_2samp(flow.arr_dist, approx))
        print "Beta: {}".format(stats.ks_2samp(flow.arr_dist, approx_b))
        print "BiMod: {}".format(stats.ks_2samp(flow.arr_dist, approx_c))
        print "KDE: {}".format(stats.ks_2samp(flow.arr_dist, approx_d))

        ax.legend()
        #plt.show()

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


    def evaluate_generate(self):
        gen_sizes = []
        rea_sizes = []
        diff_avg_size = 0
        ndiff_size = 0

        gen_dur = []
        rea_dur = []
        diff_avg_dur = 0
        ndiff_dur = 0

        biggest_dur_flow = None 
        biggest_dur = 0

        biggest_diff_flow = None
        biggest_diff_dur = 0

        try:

            for flow in self.flows.values():
                gen_clt_size = np.sum(flow.generate_client_pkts(flow.nb_pkt))
                gen_sizes.append(gen_clt_size)
                rea_sizes.append(flow.size)
                diff_avg_size += abs(gen_clt_size - flow.size)
                ndiff_size += 1

                if flow.in_estim_pkt is not None:
                    gen_srv_size = np.sum(flow.generate_server_pkts(flow.in_nb_pkt))
                    gen_sizes.append(gen_srv_size)
                    rea_sizes.append(flow.in_size)
                    diff_avg_size += abs(gen_srv_size - flow.in_size)
                    ndiff_size += 1

                gen_clt_dur = np.sum(flow.generate_client_arrs(len(flow.arr_dist)))
                rea_clt_dur = np.sum(flow.arr_dist)
                if gen_clt_dur < 0:
                    pass
                    #pdb.set_trace()
                gen_dur.append(gen_clt_dur)
                rea_dur.append(rea_clt_dur)
                diff = abs(gen_clt_dur - rea_clt_dur)
                diff_avg_dur += diff
                ndiff_dur += 1

                if gen_clt_dur > biggest_dur:
                    biggest_dur_flow = flow.key
                    biggest_dur = gen_clt_dur

                if diff > biggest_diff_dur:
                    biggest_diff_flow = flow.key
                    biggest_diff_dur = diff


                if flow.in_estim_arr is not None:
                    gen_srv_dur = np.sum(flow.generate_server_arrs(len(flow.in_arr_dist)))
                    rea_srv_dur = np.sum(flow.in_arr_dist)
                    if gen_srv_dur < 0:
                        pass
                        #pdb.set_trace()
                    gen_dur.append(gen_srv_dur)
                    rea_dur.append(rea_srv_dur)
                    diff = abs(gen_srv_dur - rea_srv_dur)
                    diff_avg_dur += diff
                    ndiff_dur += 1

                    if gen_clt_dur > biggest_dur:
                        biggest_dur_flow = flow.key
                        biggest_dur = gen_clt_dur

                    if diff > biggest_diff_dur:
                        biggest_diff_flow = flow.key
                        biggest_diff_dur = diff


        except ValueError:
            traceback.print_exc()
            print "Flow: {}".format(flow)
            print "Pkt Estimator: {}".format(flow.estim_pkt.distribution)
            print "Arr Estimator: {}".format(flow.estim_arr.distribution)

        except AttributeError:
            traceback.print_exc()
            print "Flow: {}".format(flow)
            print "Pkt Estimator: {}".format(flow.estim_pkt.distribution)
            print "Arr Estimator: {}".format(flow.estim_arr.distribution)

        ind = np.arange(2)

        fig, axes = plt.subplots(2, 2)

        genval = np.min(gen_sizes)
        reaval = np.min(rea_sizes)
        print "Gen Min size: {}".format(genval)
        print "Min size: {}".format(reaval)
        print "Diff: {}".format(abs(genval - reaval))

        genval = np.average(gen_sizes)
        reaval = np.average(rea_sizes)
        print "Gen Avg size: {}".format(np.average(gen_sizes))
        print "Avg size: {}".format(np.average(rea_sizes))
        print "Diff: {}".format(abs(genval - reaval))
        ax = axes[0, 0]
        ax.set_ylim(util.compute_axis_scale([reaval, genval]))
        ax.bar(ind, [reaval, genval])
        ax.set_xticks(ind)
        ax.set_xticklabels(["Real", "Gen"])
        ax.set_title("Average Size (B)")

        genval = np.max(gen_sizes)
        reaval = np.max(rea_sizes)
        print "Gen Max size: {}".format(np.max(gen_sizes))
        print "Max size: {}".format(np.max(rea_sizes))
        print "Diff: {}".format(abs(genval - reaval))
        ax = axes[0, 1]
        ax.set_ylim(util.compute_axis_scale([reaval, genval]))
        ax.bar(ind, [reaval, genval])
        ax.set_xticks(ind)
        ax.set_xticklabels(["Real", "Gen"])
        ax.set_title("Max Size (B)")

        print "MSE size: {}".format(diff_avg_size/float(ndiff_size))
        print "----------------------------------------"

        genval = np.min(gen_dur)
        reaval = np.min(rea_dur)
        print "Gen Min dur: {}".format(np.min(gen_dur))
        print "Min dur: {}".format(np.min(rea_dur))
        print "Diff: {}".format(abs(genval - reaval))
        
        genval = np.average(gen_dur)
        reaval = np.average(rea_dur)
        print "Gen Avg dur: {}".format(np.average(gen_dur))
        print "Avg dur: {}".format(np.average(rea_dur))
        print "Diff: {}".format(abs(genval - reaval))
        ax = axes[1, 0]
        ax.set_ylim(util.compute_axis_scale([reaval, genval]))
        ax.bar(ind, [reaval, genval])
        ax.set_xticks(ind)
        ax.set_xticklabels(["Real", "Gen"])
        ax.set_title("Avg dur (ms)")

        genval = np.max(gen_dur)
        reaval = np.max(rea_dur)
        print "Gen Max dur: {}".format(np.max(gen_dur))
        print "Max dur: {}".format(np.max(rea_dur))
        print "Diff: {}".format(abs(genval - reaval))
        ax = axes[1, 1]
        ax.set_ylim(util.compute_axis_scale([reaval, genval]))
        ax.bar(ind, [reaval, genval])
        ax.set_xticks(ind)
        ax.set_xticklabels(["Real", "Gen"])
        ax.set_title("Max dur (ms)")

        print "Biggest diff: {}".format(biggest_diff_dur)
        print "Biggest Flow diff: {}".format(biggest_diff_flow)
        print "MSE dur: {}".format(diff_avg_dur/float(ndiff_dur))
        plt.show()

        return biggest_diff_flow

    def show_clusters(self, clusters):
        sizes = [len(x.flows) for x in clusters]
        nb = len(clusters)
        fig = plt.figure(figsize=(10,10))
        plt.scatter(np.linspace(0, nb-1, nb), sizes)
        plt.show()


def main(config, duration, saveflow=None, loadflow=None, 
            savedist=None, loaddist=None):
    handler = FlowHandler(config, saveflow, loadflow, savedist, loaddist)
    #clusters = clustering.clustering(handler.distances, FlowHandler.NB_CLUSTER,
    #                                 FlowHandler.MIN_DIST)
    #handler.estimate_cluster(clusters)
    i = handler.evaluate_generate()
    handler.plot_flow_dist(i)
    pdb.set_trace()
    #handler.display_flow_dist(0)
    #flow = handler.flows.values()[0]
    #handler.run(duration)
    #handler.estimate_distribution(handler.flows.values()[0], 10)

if __name__ == "__main__":
    main(args.config, args.duration, 
         args.saveflow, args.loadflow,
         args.savedist, args.loaddist)
