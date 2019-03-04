import os
import cPickle as pickle
import time
import thread
import zlib
import argparse
import pdb
from itertools import izip_longest
from datetime import datetime
from subprocess  import Popen, call
from threading import Thread, Event
from flowHandler import FlowHandler
from flows import FlowStats, Flow, FlowLazyGen
from util import timeout_decorator
from util import datetime_to_ms
from util import MaxAttemptException
from util import TimedoutException
from util import write_message
from scapy.all import *

parser = argparse.ArgumentParser()
parser.add_argument("--conf", type=str, dest="config", action="store")
parser.add_argument("--flowid", type=int, dest="flowid", action="store")
parser.add_argument("--outfile", type=str, dest="outfile", action="store")
parser.add_argument("--writepcap", type=str, dest="writepcap", action="store")
parser.add_argument("--infile", type=str, dest="infile", action="store")
args = parser.parse_args()

class Sniffer(Thread):
    def __init__(self, filename, interface="lo", fltr= "ip"):
        Thread.__init__(self)
        self.intf = interface
        self.filter = fltr
        self.ipt = {}
        self.filename = filename
        self.daemon = True
        self.socket = None
        self.stop = Event()

    def pkt_callback(self, pkt):
        wrpcap(self.filename, pkt, append=True)

    def run(self):
        self.socket = conf.L2listen(type=ETH_P_ALL,
                                    iface=self.intf,
                                    filter=self.filter)
        sniff(opened_socket=self.socket,
              prn=self.pkt_callback,
              stop_filter=self.should_stop_sniffer)

    def join(self, timeout=None):
        self.stop.set()
        Thread.join(self, timeout)

    def should_stop_sniffer(self, pkt):
        return self.stop.isSet()


class PCAPReader(object):
    def __init__(self, filename, fltr="ip"):
        self.filename = filename
        self.filter = fltr
        self.ipt = {}

    def pkt_callback(self, pkt):
        if IP in pkt:
            srcip = str(pkt[IP].src)
            sport = None
            if TCP in pkt:
                sport = str(pkt[TCP].sport)
            elif UDP in pkt:
                sport = str(pkt[UDP].sport)
            if sport:
                key = ":".join([srcip, sport])
                if key not in self.ipt:
                    self.ipt[key] = (pkt.time*1000, [])
                else:
                    last_time, arrs = self.ipt[key]
                    ipt = pkt.time*1000 - last_time
                    arrs.append(ipt)
                    self.ipt[key] = (pkt.time*1000, arrs)

    def run(self):
        sniff(offline=self.filename, prn=self.pkt_callback, filter=self.filter)

@timeout_decorator()
def pipe_created(name):
    return os.path.exists(name)

def write(msg, p):
    length = '{0:04d}'.format(len(msg))
    os.write(p, b'X')
    os.write(p, length.encode('utf-8'))
    os.write(p, msg)

def read_generated(config, flowid, outfile, writepcap):
    try:
        handler = FlowHandler(config)
        flow = handler.flows.values()[flowid]
        pdb.set_trace()

        proto = "tcp" if flow.proto == 6 else "udp"

        server_ps = flow.in_estim_pkt
        server_ipt = flow.in_estim_arr

        client_ps = flow.estim_pkt
        client_ipt = flow.estim_arr

        server_first = datetime_to_ms(flow.in_first)
        client_first = datetime_to_ms(flow.first)

        if flow.is_client_flow:
            sport = flow.sport
            dport = flow.dport

            flowstat_client = FlowLazyGen(client_first, server_first,
                                          flow.nb_pkt, flow.in_nb_pkt,
                                          client_ps, client_ipt)

            flowstat_server = FlowLazyGen(server_first, client_first,
                                          flow.in_nb_pkt, flow.nb_pkt,
                                          server_ps, server_ipt)
        else:
            sport = flow.dport
            dport = flow.sport

            flowstat_client = FlowLazyGen(server_first, client_first,
                                          flow.in_nb_pkt, flow.nb_pkt,
                                          server_ps, server_ipt)

            flowstat_server = FlowLazyGen(client_first, server_first,
                                          flow.nb_pkt, flow.in_nb_pkt,
                                          client_ps, client_ipt)
        client_pipe = "pipe_client"
        server_pipe = "pipe_server"
        temppcap = os.path.join("/tmp", "flowtest")

        if os.path.exists(temppcap):
            os.remove(temppcap)

        sniffer = Sniffer(temppcap, "lo",
                          "(tcp or udp) and (port {} and port {})".format(sport,
                                                                          dport))
        print "[*] Start sniffing..."
        sniffer.start()

        if os.path.exists(client_pipe):
            os.remove(client_pipe)

        if os.path.exists(server_pipe):
            os.remove(server_pipe)

        server_proc = Popen(["python", "server.py", "--addr", "127.0.0.2",
                             "--port", "{}".format(dport), "--proto",
                             "{}".format(proto), "--pipe", server_pipe])
        try:
            pipe_created(server_pipe)
        except MaxAttemptException as e:
            print "%s" % (e.msg)
            return
        except TimedoutException as e:
            print "%s" % (e.msg)
            return

        server_pipein = os.open(server_pipe, os.O_NONBLOCK|os.O_WRONLY)
        write_message(server_pipein, pickle.dumps(flowstat_server))
        print "[*] Writing Server stat"

        client_proc = Popen(["python", "client.py", "--saddr", "127.0.0.3",
                             "--daddr", "127.0.0.2", "--sport", "{}".format(sport), "--dport",
                             "{}".format(dport), "--proto", "{}".format(proto), "--pipe", client_pipe])
        try:
            pipe_created(client_pipe)
        except MaxAttemptException as e:
            print "%s" % (e.msg)
            return
        except TimedoutException as e:
            print "%s" % (e.msg)
            return

        client_pipein = os.open(client_pipe, os.O_NONBLOCK|os.O_WRONLY)
        write_message(client_pipein, pickle.dumps(flowstat_client))
        print "[*] Writting Client stat"
        client_proc.wait()
        os.close(client_pipein)

        call(["editcap", "-D", "100", temppcap, writepcap])

        print "[*] Client done"
        server_proc.wait()
    except KeyboardInterrupt:
        server_proc.kill()
        os.close(server_pipein)
        call(["pkill", "-f", "python client.py"])
        call(["pkill", "-f", "python server.py"])
        print "[*] Server done"
        print "[*] Stop sniffing..."

        sniffer.join(2.0)
        if sniffer.isAlive():
            sniffer.socket.close()

        reader = PCAPReader(writepcap, "(tcp or udp) and (port {} and port {})".format(sport,
                                                                                       dport))
        reader.run()

        with open(outfile, 'w') as f:
            for k, v in reader.ipt.items():
                f.write("{} emudur:{} ".format(k, sum(v[1])))
                arrs = []
                if flow.is_client_flow:
                    if str(sport) in k:
                        arrs = v[1]
                    elif str(dport) in k:
                        arrs = v[1]
                else:
                    if str(sport) in k:
                        arrs = v[1]
                    elif str(dport) in k:
                        arrs = v[1]

                #f.write("gendur: {} \n".format(dur))
                for ipt in arrs:
                    text = "{},".format(ipt)
                    f.write(text)

def read_empirical(config, flowid, filename, outfile):
    handler = FlowHandler(config)
    flow = handler.flows.values()[flowid]
    if flow.is_client_flow:
        sport = flow.sport
        dport = flow.dport
    else:
        sport = flow.dport
        dport = flow.sport

    reader = PCAPReader(filename, "(tcp or udp) and (port {} and port {})".format(sport,
                                                                                  dport))
    reader.run()
    with open(outfile, 'w') as f:
        for k, v in reader.ipt.items():
            f.write("{} dur:{}\n".format(k, sum(v[1])))
            for ipt in v[1]:
                text = "{}\n".format(ipt)
                f.write(text)

if __name__ == "__main__":
    try:
        if args.infile:
            print "Reading from file"
            read_empirical(args.config, args.flowid, args.infile, args.outfile)
        else:
            print "Generating flow to read"
            read_generated(args.config, args.flowid, args.outfile,
                           args.writepcap)
    finally:
        os.system('pkill -f "python server.py"')
        os.system('pkill -f "python client.py"')
