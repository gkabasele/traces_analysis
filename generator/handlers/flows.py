#!/usr/bin/python
import numpy as np
import math
import scipy as sp
import scipy.stats as stats


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



class Flow(object):

    key_attr = ["srcip", "dstip", "sport", "dport", "proto", "first", "cat"]

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
        #Distribution are represented as a list of one or several tuple
        #with the first elem being the distribution and the second the
        #its weight
        self.estim_pkt = None
        self.estim_arr = None

        self.in_estim_pkt = None
        self.in_estim_arr = None

    def __getattribute__(self, attr):
        if attr in Flow.key_attr:
            return getattr(self.key, attr)
        else:
            return super(Flow, self).__getattribute__(attr)

    def __setattr__(self, attr, value):
        if attr in Flow.key_attr:
            setattr(self.key, value)
        else:
            super(Flow, self).__setattr__(attr, value)

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
