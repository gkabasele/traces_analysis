#!/usr/bin/pythonclass Flow(object):

class Flow(object):

    """
        This class represent a flow
    """

    def __init__(self, srcip = None, dstip = None, sport = None,
                 dport=None, proto=None, duration=None, size=None,
                 nb_pkt=None, first=None, pkt_dist=None, arr_dist=None):

        self.srcip = srcip
        self.dstip = dstip
        self.sport = sport
        self.dport = dport
        self.proto = proto
        
        # fixed value
        self.dur = duration
        self.size = size
        self.nb_pkt = nb_pkt

        self.first = first

        # empirical distribution
        self.pkt_dist = pkt_dist
        self.arr_dist = arr_dist



    """
        Read file to get the empirical distribution
    """
    def configure(self, filename):
        pass

    """
        string representation
    """
    def __str__(self):
        return "{}:{}-->{}:{} ({})".format(
            self.srcip, self.sport, self.dstip, self.dport, self.proto)

    def __repr__(self):
        return self.__str__()

    def __eq__(self, other):
        return (self.srcip == other.srcip and self.dstip == other.dstip and
                self.sport == other.sport and self.dport == self.dport and
                self.proto == other.proto)

class FlowCategory(object):

    """
        This class reprensent the different types of flow (automation, human, ...
    """

    def __init__(self, flows):
        self.flows = flows

    """
        Retrieve the next flow from the category
    """

    def get_next_flow(self):
        pass
