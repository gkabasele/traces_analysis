#!/usr/bin/pythonclass Flow(object):

key_attr = ["srcip", "dstip", "sport", "dport", "proto", "first"]

class FlowKey(object):


    def __init__(self, srcip=None, dstip=None, sport=None,
                 dport=None, proto=None, first=None):

        self.srcip = srcip
        self.dstip = dstip
        self.sport = sport
        self.dport = dport
        self.proto = proto
        self.first = first

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

    """
        This class represent a flow
    """

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


    def __getattribute__(self, attr):
        if attr in key_attr:
            return getattr(self.key, attr)
        else:
            return super(Flow, self).__getattribute__(attr)

    def __setattr__(self, attr, value):
        if attr in key_attr:
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

    def __init__(self, name, flows):
        self.name = name
        self.flows = flows

    """
        Retrieve the next flow from the category
    """

    def get_next_flow(self):
        pass
