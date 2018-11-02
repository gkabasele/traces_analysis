#!/usr/bin/python

class Flow(object):

    """
        This class represent a flow
    """

    def __init__(self):
        self.srcip = None
        self.dstip = None
        self.sport = None
        self.dport = None
        self.proto = None
        
        # fixed value
        self.duration = None
        self.size = None

        # empirical distribution
        self.packet_dist = None
        self.packet_arrival = None


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

    def get_next_flow(self)
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
