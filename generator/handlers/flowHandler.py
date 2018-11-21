#!/usr/bin/python
import struct
import os
import argparse
import time
import bisect
from flows import Flow
from flows import FlowKey
from ipaddress import IPv4Address
from networkHandler import NetworkHandler
from networkHandler import GenTopo
from mininet.net import Mininet
from mininet.util import dumpNodeConnections
from threading import Lock
from util import RepeatedTimer
from datetime import datetime
from datetime import timedelta


parser = argparse.ArgumentParser()
parser.add_argument("-f", type=str, dest="filename", action="store", help="input binary file")
parser.add_argument("-o", type=str, dest="output", action="store")
parser.add_argument("-d", type=int, dest="duration", action="store")

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
        self.flowseq = []
        self.flows = self.retrieve_flows(filename)

    def read(self, _type, readsize, f):
        self.index += readsize
        return struct.unpack(_type, f.read(readsize))[0] 

    def retrieve_flows(self, filename):
        flows = {}
        with open(filename, "rb") as f:
            filesize = os.path.getsize(filename)
            while self.index < filesize:
                srcip = IPv4Address(self.read('>I', 4, f))
                dstip = IPv4Address(self.read('>I', 4, f))
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

                key = FlowKey(srcip, dstip, sport, dport, proto, first)
                bisect.insort(self.flowseq, key)
                flow = Flow(key, duration, size, nb_pkt,
                            pkt_dist, arr_dist)

                flows[flow.key] = flow
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


def main(filename, output, duration):

    handler = FlowHandler(filename)
    print handler.flowseq

    '''
    sw_cli = "s1"
    sw_host = "s2"
    lock = Lock()
    topo = GenTopo(sw_cli, sw_host)
    net = Mininet(topo)
    net_handler = NetworkHandler(net, lock)
    collector = None
    net_handler.run(output)

    time.sleep(1)
    start_time = time.time()
    elasped_time = 0

    cleaner = RepeatedTimer(5, net_handler.remove_done_host)
    i = 0
    while elasped_time < duration:
        if i < len(handler.flows):
            f = handler.flows[i]
            i += 1
            net_handler.establish_conn_client_server(f, collector)
        time.sleep(0.2)
        elasped_time = time.time() - start_time

    dumpNodeConnections(net.hosts)

    cleaner.stop()
    net_handler.stop()
    '''

if __name__ == "__main__":
    main(args.filename, args.output, args.duration)
