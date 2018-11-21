#!/usr/bin/python
import struct
import os
import argparse
import socket
from flows import Flow
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
                self.read('BBB', 3, f) # Padding

                size = self.read('Q', 8, f)

                nb_pkt = self.read('Q', 8, f)

                first_sec = self.read('Q', 8, f)
                first_micro = self.read('Q', 8, f)
                first = (first_sec, first_micro)

                duration = self.read('f', 4, f)

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

                flow = Flow(srcip, dstip, sport, dport, proto, first, duration,
                        size, nb_pkt, pkt_dist, arr_dist)
                flows.append(flow)
        self.index = 0
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
