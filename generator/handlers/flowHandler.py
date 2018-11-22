#!/usr/bin/python
import struct
import os
import argparse
import time
import bisect
import yaml
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
parser.add_argument("-d", type=int, dest="duration", action="store")
parser.add_argument("-c", type=str, dest="config", action="store")

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

    def __init__(self, config):

        with open(config, 'r') as stream:
            try:
                conf = yaml.load(stream)
            except yaml.YAMLError as exc:
                print exc
                return

            filename = conf['input']

            self.index = 0
            self.flowseq = []
            self.flows = self.retrieve_flows(filename)

            appli = conf['application']

            self.flow_corr = {}
            self.categories = {}
            self.create_categorie(appli)
            self.compute_flow_corr()

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

                key_out = FlowKey(srcip, dstip, sport, dport, proto, first)
                key_in = FlowKey(dstip, srcip, dport, sport, proto, None)

                if key_in in flows:
                    flow = flows[key_in]
                    flow.set_reverse_stats(duration, size, nb_pkt, pkt_dist,
                                           arr_dist)
                elif key_out not in flows:
                    flow = Flow(key_out, duration, size, nb_pkt, pkt_dist,
                                arr_dist)
                    flows[flow.key] = flow
                    bisect.insort(self.flowseq, key_out)

        self.index = 0
        return flows

    def create_categorie(self, appli):
        for k in appli:
            self.categories[k] = {}

    def compute_flow_corr(self):
        i = 0
        while i < len(self.flowseq) - 1:
            cur_dport = str(self.flowseq[i].dport)
            cur_sport = str(self.flowseq[i].sport)
            next_dport = str(self.flowseq[i+1].dport)
            next_sport = str(self.flowseq[i+1].sport)
            if cur_dport in self.categories:
                if next_dport in self.categories:
                    if next_dport in self.categories[cur_dport]:
                        self.categories[cur_dport][next_dport] += 1
                    else:
                        self.categories[cur_dport][next_dport] = 1

                elif next_sport in self.categories:
                    if next_sport in self.categories[cur_dport]:
                        self.categories[cur_dport][next_sport] += 1
                    else:
                        self.categories[cur_dport][next_sport] = 1

            if cur_sport in self.categories:
                if next_dport in self.categories:
                    if next_dport in self.categories[cur_sport]:
                        self.categories[cur_sport][next_dport] += 1
                    else:
                        self.categories[cur_sport][next_dport] = 1
                elif next_sport in self.categories:
                    if next_sport in self.categories[cur_sport]:
                        self.categories[cur_sport][next_dport] += 1
                    else:
                        self.categories[cur_sport][next_dport] = 1
            i += 1

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


def main(config, duration):

    handler = FlowHandler(config)
    print handler.flowseq
    print handler.categories

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
    main(args.config, args.duration)
