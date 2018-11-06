#!/usr/bin/python

class Flow(object):

    """
        This class represent a flow
    """

    def __init__(self, srcip = None, dstip = None, sport = None, 
                dport = None, proto = None, duration = None, size = None,
                nb_pkt = None, pkt_dist = None, pkt_arr = None):

        self.srcip = srcip
        self.dstip = dstip
        self.sport = sport
        self.dport = dport
        self.proto = proto
        
        # fixed value
        self.dur = duration
        self.size = size
        self.nb_pkt = nb_pkt

        # empirical distribution
        self.pkt_dist = pkt_dist
        self.pkt_arr = pkt_arr



    """
        Read file to get the empirical distribution
    """
    def configure(self, filename):
        pass

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



class FlowHandler(object):

    """
        This is the main class coordinating the creation/deletion of flows
    """

    def __init__(self, categories):

        self.categories = categories

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

    def run(duration):
        pass
