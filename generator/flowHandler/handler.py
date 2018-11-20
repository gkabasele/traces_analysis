#!/usr/bin/python
import struct
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

        self.flows = self.retrieve_flows(filename)

    def retrieve_flows(self, filename):
        flows = []
        with open(filename, "rb") as f:
            #srcip = struct.unpack('I', f.read(4))[0]
            srcip = f.read(4).encode('hex')
            #dstip = struct.unpack('I', f.read(4))[0]
            dstip = f.read(4).encode('hex') 
            sport = struct.unpack('H', f.read(2))[0]
            dport = struct.unpack('H', f.read(2))[0]
            proto = struct.unpack('B', f.read(1))[0]
            padding = struct.unpack('BBB', f.read(3))[0]

            size = struct.unpack('Q', f.read(8))[0]
            print size

            nb_pkt = struct.unpack('Q', f.read(8))[0]
            print nb_pkt

            first_sec = struct.unpack('Q', f.read(8))[0]
            first_micro = struct.unpack('Q', f.read(8))[0]
            first = (first_sec, first_micro)

            duration = struct.unpack('f', f.read(4))[0]
            print duration

            size_list = struct.unpack('Q', f.read(8))[0]
            print size_list

            pkt_dist = []
            while size_list > 0:
                val = struct.unpack('H', f.read(2))[0]
                pkt_dist.append(val)
                size_list -= 1
            print pkt_dist

            size_list = struct.unpack('Q', f.read(8))[0]
            print size_list
            arr_dist = []
            while size_list > 0:
                val = struct.unpack('f', f.read(4))[0]
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
