#!/usr/bin/python
import argparse
import string
import sys
import random
import time
import threading
sys.path.append('core/')
from handler import Flow
from util import RepeatedTimer
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.util import irange
from mininet.util import dumpNodeConnections
from mininet.log import setLogLevel
from mininet.cli import CLI


parser = argparse.ArgumentParser()
parser.add_argument("--debug", type=str, dest="debug", action="store", help="enable CLI for debug")
parser.add_argument("--dur", type=int, dest="duration", action="store", help="duration of the generation")

args = parser.parse_args()
debug = args.debug
duration = args.duration

TCP = 6
UDP = 17

class GenTopo(Topo):
   #
   #    C --------------Hub------------ S
   #

   def __init__(self, sw_a, sw_b, **opts):

        super(GenTopo, self).__init__(**opts)

        self.cli_sw_name = sw_a
        self.srv_sw_name = sw_b

        cli_sw = self.addSwitch(sw_a)
        srv_sw = self.addSwitch(sw_b)
        self.addLink(cli_sw, srv_sw)

        client = self.addHost("cl1")
        self.addLink(client, cli_sw)

        server = self.addHost("sr1")
        self.addLink(server, srv_sw)

        self.cli_intf  = 3
        self.srv_intf  = 3

class HostCollector(object):

    def __init__(self, lock):
        self.hosts = set()
        self.__is_shut_down = threading.Event()
        self.__shutdown_request = False
        self.lock = lock


    def add_host(self, host):
        self.hosts.add(host)

    def del_host(self, host):
        self.hosts.remove(host)

    def check_hosts_activity(self, to_remove):
        self.lock.acquire()
        to_remove.clear()
        for host in self.hosts:
            cmd = "netstat -tulpn | grep -E \'client|server\'"
            output = host.cmd(cmd)
            if not output:
                to_remove.append(host)
        self.lock.release()

    def parse_netstat_output(self, text):
        # Netstat output
        #tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      569/systemd-resolve
        pass

    def stop(self):
        self.is_running = False

    def run(self, to_remove):

        rt = RepeatedTimer(5, check_host_activity, to_remove)
        self.__is_shut_down.clear()

        try:

            while not self.__shutdown_request:
                time.sleep(10)
                if self.__shutdown_request:
                    break
        finally:
            rt.stop()
            self.__shutdown_request = False
            self.__is_shut_down.set()

    def shutdown(self):

        self.__shutdown_request = True
        self.__is_shut_down.wait()
    

class NetworkHandler(object):

    """
        This class manage the network by connecting to mininet
    """

    ALPHA = list(string.ascii_lowercase)

    def __init__(self, net, lock, **opts):
        self.net = net
        self.mapping_ip_host = {} # get the name of an host from IP
        self.mapping_ip_ts = {} # get the timestamp of when the host run
        self.mapping_host_intf = {} # get interface name to which the host is connected
        self.mapping_server_client = {} # keep track of existing connection
        self.cli_sw = net.get(net.topo.cli_sw_name)
        self.srv_sw = net.get(net.topo.srv_sw_name)
        self.lock = lock

    @classmethod
    def get_new_name(cls, client=True):
        s = "c-" if client else "s-"

        for x in range(4):
            s += cls.ALPHA[random.randint(0, len(cls.ALPHA) - 1)]

        return s 

    def _add_host(self, name, ip, intf):
        if name in self.mapping_ip_host or name in self.mapping_host_intf:
            raise ValueError("Name %s already exist" % name)
        self.mapping_ip_host[ip] = name
        self.mapping_host_intf[name] = intf

    def _del_host(self, name):
        if name not in self.mapping_host_intf or name not in self.mapping_ip_host:
            raise KeyError("Name %s does not exist" % name)

        self.mapping_ip_host.pop(ip, None)
        self.mapping_host_intf.pop(name, None)

    def _get_switch(self, is_client):
        return self.cli_sw if is_client else self.srv_sw


    def add_host(self, name, ip, client_ip = None):
        if client_ip:
            intf = self.net.topo.cli_sw_name + "-eth%s" % (self.net.topo.cli_intf)
        else:
            intf = self.net.topo.srv_sw_name + "-eth%s" % (self.net.topo.srv_intf)

        p_ip = client_ip if client_ip else ip
        print "Adding Host %s with IP %s on interface %s" % (name, p_ip, intf)

        self._add_host(name, ip, intf)
        self.net.addHost(name)
        host = self.net.get(name)
        switch = self._get_switch(client_ip)
        link = self.net.addLink(host, switch)
        host.setIP(client_ip) if client_ip else host.setIP(ip)
        switch.attach(link.intf1)
        switch.attach(intf)

        if client_ip:
            self.mapping_ip_host[client_ip] = name
        else:
            self.mapping_ip_host[ip] = name

        self.mapping_host_intf[name] = intf

        if client_ip:
            self.net.topo.cli_intf += 1
        else:
            self.net.topo.srv_intf += 1

    def remove_host(self, name, is_client=True):
        if name not in self.mapping_host_intf:
            raise KeyError("Name %s does not exist" % name)

        intf = self.mapping_host_intf[name]
        switch = self._get_switch(is_client)
        switch.detach(intf)
        host = self.net.get(name)
        self.net.delLinkBetween(switch, host)
        self.net.delHost(host)
        self._del_host(name)

    def send_ping(self, src_name, dstip):

        client = self.net.get(src_name)
        output = client.cmd("ping -c1 %s" % dstip)
        print output

    def establish_conn_client_server(self, flow, collector):
        #TODO ADD to dictionary
        #cli_name = self.mapping_ip_host[flow.srcip]
        #srv_name = self.mapping_ip_host[flow.dstip]

        dst = NetworkHandler.get_new_name()
        src = NetworkHandler.get_new_name(False)

        self.add_host(src, flow.srcip)
        self.add_host(dst, flow.srcip, flow.dstip) 

        client = self.net.get(dst)
        server = self.net.get(src)

        proto = 'tcp' if flow.proto == 6 else 'udp'

        cmd = ("python3 server.py --addr %s --port %s --proto %s&" %
                (flow.dstip, flow.dport, proto)) 

        server.cmd(cmd)

        cmd = ("python3 client.py --saddr %s --daddr %s --sport %s --dport %s " % 
                (flow.srcip, flow.dstip, flow.sport, flow.dport) + 
               "--proto %s --dur %s --size %s --nbr %s &" % 
               (proto, flow.dur, flow.size, flow.nb_pkt) )

        output = client.cmd(cmd)
        print output

        

        #TODO check output and kill (netstat) process accordingly
        #collector.add_host(client)
        #collector.add_host(server)
    
    def run(self, debug=None):

        output = self.cli_sw.cmd("tcpdump -i %s-eth1 -n -w gen.pcap &" % self.net.topo.cli_sw_name)
        print output
        print "Starting Network Handler"
        self.net.start()
        if debug:
            CLI(self.net)

    def stop(self):
        print "Stopping Network Handler"
        self.net.stop()

def main():

    sw_cli = "s1"
    sw_host = "s2"
    lock = threading.Lock()
    topo = GenTopo(sw_cli, sw_host)
    net = Mininet(topo)
    handler = NetworkHandler(net, lock)
    #collector = HostCollector(lock)
    collector = None
    handler.run(debug)

    start_time = time.time()
    elasped_time = 0
    i = 0

    f1 = Flow("10.0.0.3", "10.0.0.4", "3000", "8080", UDP, 21, 1248, 16) 
    f2 = Flow("10.0.0.5", "10.0.0.6", "3000", "8080", TCP, 9, 152, 3) 
    f3 = Flow("10.0.0.7", "10.0.0.8", "3000", "8080", TCP, 42, 2642, 34) 
    flows = [f1, f2, f3]

    while elasped_time < duration:
        if i < len(flows):
            f = flows[i]
            i += 1
            handler.establish_conn_client_server(f, collector)
        time.sleep(0.2)
        elasped_time = time.time() - start_time
    handler.stop()

    """
    handler.add_host("server", "10.0.0.4", 8080)
    handler.add_host("client", "10.0.0.4", 8080,"10.0.0.3")
    print "Dumping host connections"
    dumpNodeConnections(net.hosts)
    print "Testing network connectivity"
    net.pingAll()
    print "Ready !"
    handler.run()
    f = Flow("10.0.0.3", "10.0.0.4", "3000", "8080", 6, 20, 15000, 100) 
    handler.establish_conn_client_server(f)
    CLI(net)
    net.stop()
    """

if __name__ == "__main__":
    setLogLevel("info")
    main()

