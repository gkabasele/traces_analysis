import os
import cPickle as pickle
import sys
import zlib
import argparse
import pdb
from subprocess  import Popen, call
from threading import Thread, Event
from scapy.data import ETH_P_ALL
from scapy.layers.inet import IP, TCP, UDP
from scapy.all import sniff, conf, wrpcap

from handlers.flowHandler import FlowHandler
from handlers.flows import FlowLazyGen
from handlers.util import timeout_decorator
from handlers.util import datetime_to_ms
from handlers.util import MaxAttemptException
from handlers.util import TimedoutException
from handlers.flowDAO import FlowRequestPipeWriter, FlowRequestSockWriter

parser = argparse.ArgumentParser()
parser.add_argument("--conf", type=str, dest="config", action="store")
parser.add_argument("--flowid", type=int, dest="flowid", action="store")
parser.add_argument("--outfile", type=str, dest="outfile", action="store")
parser.add_argument("--writepcap", type=str, dest="writepcap", action="store")
parser.add_argument("--infile", type=str, dest="infile", action="store")
parser.add_argument("--client", choices=["pipe", "sock"], dest="client_writer")
parser.add_argument("--server", choices=["pipe", "sock"], dest="server_writer")
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

        proto = "tcp" if flow.proto == 6 else "udp"

        server_ps = flow.in_estim_pkt
        server_ipt = flow.in_estim_arr

        client_ps = flow.estim_pkt
        client_ipt = flow.estim_arr


        server_first = datetime_to_ms(flow.in_first)
        client_first = datetime_to_ms(flow.first)

        if flow.is_client_flow:
            srcip = "127.0.0.2"
            dstip = "127.0.0.3"
            sport = flow.sport
            dport = flow.dport

            flowstat_client = FlowLazyGen(dstip, dport, flow.proto, client_first, server_first,
                                          flow.nb_pkt, flow.in_nb_pkt,
                                          client_ps, client_ipt)

            flowstat_server = FlowLazyGen(srcip, sport, flow.proto, server_first, client_first,
                                          flow.in_nb_pkt, flow.nb_pkt,
                                          server_ps, server_ipt)
        else:
            srcip = "127.0.0.3"
            dstip = "127.0.0.2"
            sport = flow.dport
            dport = flow.sport

            flowstat_client = FlowLazyGen(srcip, sport, flow.proto, server_first, client_first,
                                          flow.in_nb_pkt, flow.nb_pkt,
                                          server_ps, server_ipt)

            flowstat_server = FlowLazyGen(dstip, dport, flow.proto, client_first, server_first,
                                          flow.nb_pkt, flow.in_nb_pkt,
                                          client_ps, client_ipt)
        client_pipe = "pipe_client"
        server_pipe = "pipe_server"
        temppcap = os.path.join("/tmp", "flowtest")

        if not os.path.exists(server_pipe):
            print "[*] Creating server pipe {}".format(server_pipe)
            os.mkfifo(server_pipe)

        if not os.path.exists(client_pipe):
            print "[*] Creating client pipe {}".format(client_pipe)
            os.mkfifo(client_pipe)

        pdb.set_trace()
        if os.path.exists(temppcap):
            os.remove(temppcap)

        sniffer = Sniffer(temppcap, "lo",
                          "(tcp or udp) and (port {} and port {})".format(sport,
                                                                          dport))
        print "[*] Start sniffing..."
        sniffer.start()

        if args.server_writer == "pipe":
            try:
                pipe_created(server_pipe)
            except MaxAttemptException as err:
                print "%s" % (err.msg)
                return
            except TimedoutException as err:
                print "%s" % (err.msg)
                return

        print "[*] Running server"

        if args.server_writer != "sock":
            server_proc = Popen(["python", "-u", "server.py", "--addr", "127.0.0.2",
                                 "--port", "{}".format(dport), "--proto",
                                 "{}".format(proto), "--pipe", "pipe", "--pipename", server_pipe])
            swriter = FlowRequestPipeWriter(server_pipe)
            msg = zlib.compress(pickle.dumps(flowstat_server))
            print "[*] Writing message of {} to Server".format(len(msg))
            swriter.write(msg)
        else:
            ip = "127.0.0.1"
            port = 8081
            server_proc = Popen(["python", "-u", "server.py", "--addr", "127.0.0.2",
                                 "--port", "{}".format(dport), "--proto",
                                 "{}".format(proto), "--sock", "sock", "--sock_ip",
                                 ip, "--sock_port", "{}".format(port)])
            time.sleep(0.3)
            swriter = FlowRequestSockWriter(ip, port)
            msg = zlib.compress(pickle.dumps(flowstat_server))
            print "[*] Writing message of {} to Server".format(len(msg))
            swriter.write(msg)

        print "Message written"

        if args.client_writer == "pipe":
            try:
                pipe_created(client_pipe)
            except MaxAttemptException as err:
                print "%s" % (err.msg)
                return
            except TimedoutException as err:
                print "%s" % (err.msg)
                return

        print "[*] Running client"

        if args.client_writer != "sock":
            client_proc = Popen(["python", "-u", "client.py", "--saddr", "127.0.0.3",
                                 "--daddr", "127.0.0.2", "--sport",
                                 "{}".format(sport), "--dport", "{}".format(dport),
                                 "--proto", "{}".format(proto), "--pipe",
                                 "pipe", "--pipename", client_pipe])

            cwriter = FlowRequestPipeWriter(client_pipe)
            msg = zlib.compress(pickle.dumps(flowstat_client))
            print "[*] Writting message of {} to Client".format(len(msg))
            cwriter.write(msg)

        else:
            ip = "127.0.0.1"
            port = 8080
            client_proc = Popen(["python", "-u", "client.py", "--saddr", "127.0.0.3",
                                 "--daddr", "127.0.0.2", "--sport",
                                 "{}".format(sport), "--dport", "{}".format(dport),
                                 "--proto", "{}".format(proto), "--sock",
                                 "sock", "--ip", ip, "--port",
                                 "{}".format(port)])
            time.sleep(0.3)

            cwriter = FlowRequestSockWriter(ip, port)
            msg = zlib.compress(pickle.dumps(flowstat_client))
            print "[*] Writting message of {} to Client".format(len(msg))
            cwriter.write(msg)

        client_proc.wait()
        cwriter.close()

        print "[*] Editing pcap"

        call(["editcap", "-D", "100", temppcap, writepcap])

        print "[*] Client done"
        server_proc.wait()
    except KeyboardInterrupt:
        server_proc.kill()
        swriter.close()
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
    except Exception as err:
        print "an error occurred: {}".format(err)

        call(["pkill", "-f", "python -u client.py"])
        call(["pkill", "-f", "python -u server.py"])

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
