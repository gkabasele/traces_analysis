#!/usr/bin/python
import struct
import os
import argparse
import socket
from ctypes import sizeof
from binascii import hexlify


parser = argparse.ArgumentParser()
parser.add_argument("-f", type=str, dest="filename", action="store", help="input binary file")

args = parser.parse_args()



def swap_bytes(array, swap_size):
    res = bytearray(len(array))
    res[:swap_size] = array[swap_size:]
    res[swap_size:] = array[:swap_size]
    return res

class Flow(object):

    """
        This class represent a flow
    """

    def __init__(self, srcip = None, dstip = None, sport = None, 
                dport = None, proto = None, first=None, duration = None, 
                size = None,nb_pkt = None, pkt_dist = None, arr_dist = None):
                

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



class FlowHandler(object):

    """
        This is the main class coordinating the creation/deletion of flows
    """

    def __init__(self, filename):

        self.index = 0
        self.flows = self.retrieve_flows(filename)

    def read(self, _type, readsize, f):
        self.index += readsize
        return struct.unpack(_type, f.read(readsize))[0] 

    def retrieve_flows(self, filename):
        flows = []
        with open(filename, "rb") as f:
            filesize = os.path.getsize(filename)
            while self.index < filesize:
                srcip = self.read('I', 4, f)
                dstip = self.read('I', 4, f)
                sport = self.read('H', 2, f)
                dport = self.read('H', 2, f)
                proto = self.read('B', 1, f)
                self.read('BBB', 3, f)

                size = self.read('Q', 8, f)
                print size

                nb_pkt = self.read('Q', 8, f)
                print nb_pkt

                first_sec = self.read('Q', 8, f)
                first_micro = self.read('Q', 8, f)
                first = (first_sec, first_micro)

                duration = self.read('f', 4, f)
                print duration

                size_list = self.read('Q', 8, f)
                print size_list

                pkt_dist = []
                while size_list > 0:
                    val = self.read('H', 2, f)
                    pkt_dist.append(val)
                    size_list -= 1
                print pkt_dist

                size_list = self.read('Q', 8, f)
                print size_list
                arr_dist = []
                while size_list > 0:
                    val = self.read('f', 4, f)
                    arr_dist.append(val)
                    size_list -= 1
                print arr_dist

                flow = Flow(srcip, dstip, sport, dport, proto, first, duration,
                        size, nb_pkt, pkt_dist, arr_dist)
                flows.append(flow)
        return flows

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
        pass


def main(filename):

    handler = FlowHandler(filename)
    print handler.flows

if __name__ == "__main__":
    main(args.filename)
