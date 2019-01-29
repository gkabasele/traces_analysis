#!/usr/bin/python
import numpy as np
import math
import scipy as sp
import scipy.stats as stats
from sklearn.neighbors import KernelDensity
from abc import ABCMeta, abstractmethod

class Distribution(object):

    __metaclass__ = ABCMeta 

    @abstractmethod
    def generate(self, nsample):
        pass


class DiscreteGen(Distribution):

    #Distribution is represented as a dictionnary of frequency (Counter)

    def __init__(self, distribution):
        self.distribution = distribution

    def generate(self, nsample):
        val = self.distribution.keys()
        return np.random.choice(val, nsample, p=self.distribution.values())


class ContinuousGen(Distribution):

    #Distribution are represented as a list of one or several tuple
    #with the first elem being the distribution and the second the 
    #its weight

    def __init__(self, distribution):
        self.distribution = distribution

    def generate(self, nsample):
        sample = []
        for rv in self.distribution:
            d, w = rv
            gensize = int(nsample * w)
            if isinstance(d, stats.gaussian_kde):
                gendata = d.resample(size=gensize).reshape((gensize,))
            elif isinstance(d, KernelDensity): 
                gendata = d.sample(gensize).reshape((gensize,))
            else:
                gendata = d.rvs(gensize)

            sample = np.concatenate((
                sample,
                gendata))
        diff = abs(nsample - len(sample))
        if diff != 0:
            r = 0
            for k in xrange(diff):
                d, w = self.distribution[r]
                if isinstance(d, stats.gaussian_kde):
                    gendata = d.resample(size=1).reshape((1,))
                elif isinstance(d, KernelDensity):
                    gendata = d.sample(gensize).reshape((gensize,))
                else:
                    gendata = d.rvs(1)
                sample = np.concatenate((
                    sample,
                    gendata))
        return sample

class FlowKey(object):


    def __init__(self, srcip=None, dstip=None, sport=None,
                 dport=None, proto=None, first=None, cat=None):

        self.srcip = srcip
        self.dstip = dstip
        self.sport = sport
        self.dport = dport
        self.proto = proto
        self.first = first
        self.cat = cat

    def  __lt__(self, other):
        return self.first < other.first

    def __gt__(self, other):
        return self.first > other.first


    def __str__(self):
        return "{}:{}<->{}:{} ({})".format(
            self.srcip, self.sport, self.dstip, self.dport, self.proto)

    def __repr__(self):
        return self.__str__()

    def __eq__(self, other):
        return (self.srcip == other.srcip and self.dstip == other.dstip and
                self.sport == other.sport and self.dport == self.dport and
                self.proto == other.proto)

    def __hash__(self):
        return hash((self.srcip, self.dstip, self.sport, self.dport,
                     self.proto))

    def reverse(self, other):
        return (self.srcip == other.dstip and self.dstip == other.srcip and
                self.sport == other.dport and self.dport == other.sport and
                self.proto == other.proto)

    def strict_eq(self, other):
        return self == other and self.first == other.first

    def get_reverse(self):
        return FlowKey(self.dstip, self.srcip, self.dport, self.sport,
                       self.proto) 
    def __getstate__(self):
        return  self.__dict__

    def __setstate__(self, s):
        self.__dict__.update(s)



class Flow(object):

    key_attr = ["srcip", "dstip", "sport", "dport", "proto", "first", "cat"]

    NB_TRIALS = 15

    def __init__(self, flowkey=None,duration=None, size=None,
                 nb_pkt=None, pkt_dist=None, arr_dist=None):

        self.key = flowkey

        # fixed value
        self.dur = duration
        self.size = size
        self.nb_pkt = nb_pkt


        # empirical distribution
        self.pkt_dist = pkt_dist
        self.arr_dist = arr_dist

        # value of the flow in other direction
        self.in_dur = None
        self.in_size = None
        self.in_nb_pkt = None
        self.in_pkt_dist = None
        self.in_arr_dist = None


        #Estimated distribution
        self.estim_pkt = None
        self.estim_arr = None

        self.in_estim_pkt = None
        self.in_estim_arr = None


    def __getattr__(self, attr):
        if attr in Flow.key_attr:
            return getattr(self.key, attr)

    def __getstate__(self):
        return self.__dict__

    def __setstate__(self, s):
        self.__dict__.update(s)

    """
        string representation
    """
    def __str__(self):
        return self.key.__str__()

    def __repr__(self):
        return self.__str__()

    def __eq__(self, other):
        return self.key == other.key

    def set_reverse_stats(self, duration, size, nb_pkt, pkt_dist, arr_dist):
        self.in_dur = duration
        self.in_size = size
        self.in_nb_pkt = nb_pkt
        self.in_pkt_dist = pkt_dist
        self.in_arr_dist = arr_dist

    def get_reverse(self):
        return self.key.get_reverse()

    def display_flow_info(self):
        s = self.__str__() + "\n"
        s += "Dur: {}, Size: {}, #pks: {}\n".format(self.dur, self.size,
                                                    self.nb_pkt)

        s += "Mean Size: {}, Std: {} \n".format(np.mean(self.pkt_dist),
                                                np.std(self.pkt_dist))
        s += "Mean Arr: {}, Std: {}\n".format(np.mean(self.arr_dist),
                                              np.std(self.arr_dist))
        s += "Dist Pks: {}\n".format(self.estim_pkt)
        s += "Dist Arr: {}".format(self.estim_arr)
        return s

    def generate_client_pkts(self, n):
        return self.estim_pkt.generate(n)

    def generate_server_pkts(self, n):
        return self.in_estim_pkt.generate(n)

    def generate_client_arrs(self, n):
        if isinstance(self.estim_arr, ContinuousGen):
            return self.estim_arr.generate(n)
        else:
            emp_dur = sum(self.arr_dist)
            min_ratio = None
            min_gen_data = []
            for i in xrange(Flow.NB_TRIALS):
                gen_data = self.estim_arr.generate(n)
                error_ratio = (sum(gen_data)/float(emp_dur))
                diff_ratio = abs(1 - error_ratio)
                if min_ratio is None or diff_ratio < min_ratio:
                    min_ratio = diff_ratio
                    min_gen_data = gen_data
        return min_gen_data

    def generate_server_arrs(self, n):
        if isinstance(self.in_estim_arr, ContinuousGen):
            return self.in_estim_arr.generate(n)
        else:
            emp_dur = sum(self.arr_dist)
            min_ratio = None
            min_gen_data = []
            for i in xrange(Flow.NB_TRIALS):
                gen_data = self.estim_arr.generate(n)
                error_ratio = (sum(gen_data)/float(emp_dur))
                diff_ratio = abs(1 - error_ratio)
                if min_ratio is None or diff_ratio < min_ratio:
                    min_ratio = diff_ratio
                    min_gen_data = gen_data
        return min_gen_data

class FlowCategory(object):

    """
        This class reprensent the different types of flow (automation, human, ...
    """

    def __init__(self, port):
        self.port = port
        self.clt_size = []
        self.clt_nb_pkt = []
        self.clt_dur = []

        self.srv_size = []
        self.srv_nb_pkt = []
        self.srv_dur = []

    def add_flow_server(self, size, nb_pkt, dur):
        self.srv_size.append(size)
        self.srv_nb_pkt.append(nb_pkt)
        self.srv_dur.append(dur)

    def add_flow_client(self, size, nb_pkt, dur):
        self.clt_size.append(size)
        self.clt_nb_pkt.append(nb_pkt)
        self.clt_dur.append(dur)

    """
        Retrieve the next flow from the category
    """

    def get_next_flow(self):
        pass

    def __str__(self):
        s = "Cat: {}\n".format(self.port)

        s += "Client flows Data\n"
        s += " Size: {}\n #Pkt: {}\n Dur: {}\n".format(self.clt_size,
                                                       self.clt_nb_pkt,
                                                       self.clt_dur)
        s += "Server flows Data\n"
        s += " Size: {}\n #Pkt: {}\n Dur: {}\n".format(self.srv_size,
                                                       self.srv_nb_pkt,
                                                       self.srv_dur)
        return s

    def __repr__(self):
        return self.__str__()
