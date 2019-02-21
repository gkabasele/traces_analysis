#!/usr/bin/python
import argparse
import string
import sys
import os
import random
import time
import threading
import logging
import tempfile
import re
import pickle
from subprocess import call
from logging.handlers import RotatingFileHandler
from flows import Flow
from flows import FlowKey
from flows import FlowStats
from util import RepeatedTimer
from util import datetime_to_ms
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.util import irange
from mininet.util import dumpNodeConnections
from mininet.log import setLogLevel
from mininet.cli import CLI
from mininet.node import OVSSwitch, OVSBridge

TCP = 6
UDP = 17

logname = '../logs/networkHandler.log'

if os.path.exists(logname):
    os.remove(logname)

logger = logging.getLogger()
logger.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s :: %(levelname)s :: %(message)s')
file_handler = RotatingFileHandler('%s'%logname, 'a', 1000000, 1)
file_handler.setLevel(logging.DEBUG)
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)
setLogLevel("info")


class GenTopo(Topo):
   #
   #    C --------------Hub------------ S
   #

   def __init__(self, sw_a, sw_b, **opts):

        super(GenTopo, self).__init__(**opts)

        self.cli_sw_name = sw_a
        self.srv_sw_name = sw_b

        cli_sw = self.addSwitch(sw_a, cls=OVSSwitch, stp=True)

        srv_sw = self.addSwitch(sw_b, cls=OVSSwitch, stp=True)
        self.addLink(cli_sw, srv_sw)

        client = self.addHost("cl1")
        self.addLink(client, cli_sw)

        server = self.addHost("sr1")
        self.addLink(server, srv_sw)

        self.cli_intf = 3
        self.srv_intf = 3


class Singleton(type):
    _instances = {}
    def __call__(cls, *args, **kwargs):
        if cls not in cls._instances:
            cls._instances[cls] = super(Singleton, cls).__call__(*args,
                                                                 **kwargs)
        return cls._instances[cls]

class GenericGenTopo(Topo):

    __metaclass__ = Singleton

    def __init__(self, nb_switch, **opts):

        super(GenericGenTopo, self).__init__(**opts)
        switch_prefix = "s"

        self.switches = {}
        attributes = []

        for i in xrange(nb_switch):
            attr = switch_prefix + str(i)
            intf = 4
            if i != 0 and i != (nb_switch -1):
                intf = 3
            self.switches[attr] = intf
            sw = self.addSwitch(attr, cls=OVSSwitch, stp=True)
            attributes.append(sw)

        i = 0
        for i, c in enumerate(attributes):
            sw_a = attributes[i]
            sw_b = attributes[(i+1) % len(attributes)]
            self.addLink(sw_a, sw_b)
            i += 1

        cli = self.addHost("cl1")
        self.addLink(cli, attributes[0])

        srv = self.addHost("sr1")
        self.addLink(srv, attributes[-1])


class NetworkHandler(object):

    """
        This class manage the network by connecting to mininet
    """

    ALPHA = list(string.ascii_lowercase)

    def __init__(self, net, lock, **opts):
        self.net = net

        # get the name of an host from IP
        self.mapping_ip_host = {}

        # get the timestamp of when the host run
        self.mapping_ip_ts = {}

        # get interface name to which the host is connected
        self.mapping_host_intf = {}

        # interface where a qdisc was attached
        self.mirror_intf = set()

        # keep track of existing connection
        self.mapping_server_client = {}

        # The number of connection for each
        self.mapping_involved_connection = {}

        self.current_mac = 1

        # mac address for each host
        self.mapping_ip_mac = {}

        # flow to pid
        self.flow_to_pid = {}

        self.cli_sw = net.get(net.topo.cli_sw_name)
        self.srv_sw = net.get(net.topo.srv_sw_name)
        self.lock = lock

    def _int_to_mac(self):
        return ':'.join(['{}{}'.format(a, b)
                         for a, b
                         in zip(*[iter('{:012x}'.format(self.current_mac))]*2)])

    def _mac_to_int(self, mac):
        res = re.match('^((?:(?:[0-9a-f]{2}):){5}[0-9a-f]{2})$', mac.lower())
        if res is None:
            raise ValueError('invalid mac address')
        return int(res.group(0).replace(':', ''), 16)

    def _get_host_from_ip(self, ip):
        name = self.mapping_ip_host[ip]
        return self.net.get(name)

    @classmethod
    def get_new_name(cls, client=True):
        s = "c-" if client else "s-"

        for x in range(4):
            s += cls.ALPHA[random.randint(0, len(cls.ALPHA) - 1)]
        return s

    def get_mac_addr(self):
        mac = self._int_to_mac()
        self.current_mac += 1
        if self.current_mac >= 2**48:
            self.current_mac = 1
        return mac

    def _add_host(self, name, ip, intf):
        if name in self.mapping_ip_host or name in self.mapping_host_intf:
            raise ValueError("Name %s already exist" % name)
        self.mapping_ip_host[ip] = name
        self.mapping_host_intf[name] = intf

    def _del_host(self, ip):
        self.mapping_ip_host.pop(ip, None)
        self.mapping_host_intf.pop(ip, None)

    def _get_switch(self, is_client):
        return self.cli_sw if is_client else self.srv_sw

    def _is_service_running(self, ip, port):
        host = self._get_host_from_ip(ip)
        cmd = "netstat -tulpn | grep :%s" % port
        logger.debug("Checking if port %s open on host %s", port, ip)
        output = host.cmd(cmd)
        logger.debug("Result: %s", output)
        return (output != None and
                ("LISTEN" in output or
                 "ESTABLISHED" in output or
                 "CONNECTED" in output or
                 "udp" in output))

    def _is_client_running(self, ip, port):
        tmpdir = tempfile.gettempdir()
        filename = os.path.join(tmpdir, ip + "_" + str(port) + ".flow")
        logger.debug("Checking client %s on port %s", ip, port)
        res = os.path.exists(filename)
        logger.debug("Result: %s", res)
        return res

    def remove_done_host(self):
        self.lock.acquire()
        to_remove = []
        no_more_server = []
        logger.debug("Conn: %s", self.mapping_server_client)
        logger.debug("Involved_conn: %s", self.mapping_involved_connection)
        for server in self.mapping_server_client:
            logger.info("Server %s has %s clients", server,
                        len(self.mapping_server_client[server]))
            new_client = []
            for client in self.mapping_server_client[server]:
                client_ip = str(client.srcip)
                client_port = str(client.sport)
                if not self._is_client_running(client_ip, client_port):
                    try:
                        if client_ip in self.mapping_involved_connection:
                            self.mapping_involved_connection[client_ip] -= 1
                            self.mapping_involved_connection[server] -= 1
                            logger.info("Removing one conn for cient %s", client_ip)
                            if self.mapping_involved_connection[client_ip] == 0:
                                name = self.mapping_ip_host[client_ip]
                                self.remove_host(client_ip)
                                logger.info("Removing client %s with IP %s",
                                            name, client_ip)
                    except KeyError:
                        logger.debug("Client %s not connected to server %s",
                                     client_ip, server)
                else:
                    new_client.append(client)
            self.mapping_server_client[server] = new_client
            if self.mapping_involved_connection[server] == 0:
                to_remove.append(server)

            if len(self.mapping_server_client[server]) == 0:
                no_more_server.append(server)

        logger.debug("Server done: %s", no_more_server)
        logger.debug("Host Server done: %s", to_remove)
        for server in no_more_server:
            self.mapping_server_client.pop(server, None)

        try:
            for server in to_remove:
                name = self.mapping_ip_host[server]
                self.remove_host(server, False)
                logger.info("Removing Server %s with Ip %s",
                            name, server)
                #self.mapping_server_client.pop(server, None)
        except KeyError as e:
            logger.debug("Msg: %s", e)

        self.lock.release()

    def add_host(self, name, ip, client_ip = None):

        p_ip = client_ip if client_ip else ip

        if p_ip in self.mapping_ip_host:
            logger.debug("Trying to add existing host %s", p_ip)
            return

        if client_ip:
            intf = self.net.topo.cli_sw_name + "-eth%s" % (self.net.topo.cli_intf)
        else:
            intf = self.net.topo.srv_sw_name + "-eth%s" % (self.net.topo.srv_intf)

        logger.info("Adding Host %s with IP %s on interface %s", name, p_ip, intf)

        self.net.addHost(name)
        host = self.net.get(name)
        switch = self._get_switch(client_ip)
        link = self.net.addLink(host, switch)
        host.setIP(p_ip)
        mac = self.get_mac_addr()
        if p_ip in self.mapping_ip_mac:
            logger.debug("This address already has a mac address")
        else:
            self.mapping_ip_mac[p_ip] = mac
            logger.debug("Setting MAC %s for host %s ", mac, p_ip)
            host.setMAC(mac)

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
        return True

    def add_mirror(self, switch, in_intf, out_intf):

        cmd = "tc qdisc add dev %s ingress;:" % in_intf
        switch.cmd(cmd)

        mir_1 = ("tc filter add dev %s parent ffff: protocol ip u32 match" %
                 in_intf)
        mir_2 = "u8 0 0 action mirred egress mirror dev %s;:" % out_intf
        switch.cmd(mir_1 + " " + mir_2)

        cmd = "tc qdisc add dev %s handle 1: root prio;:" % in_intf
        switch.cmd(cmd)

        mir_1 = ("tc filter add dev %s parent 1: protocol ip u32 match" %
                 in_intf)
        mir_2 = "u8 0 0 action mirred egress mirror dev %s;:" % out_intf
        switch.cmd(mir_1 + " " + mir_2)


    def add_mirror_old(self, switch, in_intf, out_intf):
        cmd = "tc qdisc add dev %s handle ffff: ingress" % in_intf
        switch.cmd(cmd)

        mir_1 = ("tc filter add dev %s parent ffff: matchall skip_sw" %
                 in_intf)
        mir_2 = "action mirred egress mirror dev %s" % out_intf
        switch.cmd(mir_1 + " " + mir_2)

        cmd = "tc qdisc add dev %s handle 1: root prio" % in_intf
        switch.cmd(cmd)
        mir_1 = ("tc filter add dev %s parent 1: matchall skip_sw" %
                 in_intf)
        mir_2 = "action mirred egress mirror dev %s" % out_intf
        switch.cmd(mir_1 + " " + mir_2)

    def del_mirror(self, switch, in_intf):
        cmd = "tc qdisc del dev %s ingress;:" % in_intf
        switch.cmd(cmd)
        cmd = "tc qdisc del dev %s root;:" % in_intf
        switch.cmd(cmd)

    def remove_host(self, ip, is_client=True):
        try:
            name = self.mapping_ip_host[ip]
            intf = self.mapping_host_intf[name]
            switch = self._get_switch(is_client)
            if intf in self.mirror_intf:
                self.del_mirror(switch, intf)
                self.mirror_intf.discard(intf)
            switch.detach(intf)
            host = self.net.get(name)
            self.net.delLinkBetween(switch, host)
            self.net.delHost(host)
            self.mapping_ip_host.pop(ip)
            self.mapping_host_intf.pop(name)
            self.mapping_involved_connection.pop(ip)
            self.mapping_ip_mac.pop(ip)
        except KeyError:
            logger.debug("The host %s with ip %s does not exist", name, ip)
        except IndexError:
            logger.debug("No link between switch %s and host %s", switch, ip)

    def send_ping(self, src_name, dstip):

        client = self.net.get(src_name)
        client.cmd("ping -c1 %s" % dstip)

    def get_process_pipename(self, ip, port):
        tmpdir = tempfile.gettempdir()
        filename = os.path.join(tmpdir, ip + "_" + str(port) + ".flow")
        return filename

    def write_to_pipe(self, msg, p):
        length = '{0:04d}'.format(len(msg))
        os.write(p, b'X')
        os.write(p, length.encode('utf-8'))
        os.write(p, msg)

    def get_ofport(self, name):
        intf = self.mapping_host_intf[name]
        sw_name, port = intf.split("-eth")
        return port 

    def establish_conn_client_server(self, flow):

        self.lock.acquire()

        logger.info("Trying to establish flow: %s", flow)
        proto = "tcp" if flow.proto == 6 else "udp"

        server_pkt, server_arr = Flow.remove_empty_pkt(flow.generate_server_pkts(flow.in_nb_pkt),
                                                       flow.generate_server_arrs(flow.in_nb_pkt))
        
        client_pkt, client_arr = Flow.remove_empty_pkt(flow.generate_client_pkts(flow.nb_pkt),
                                                       flow.generate_client_arrs(flow.nb_pkt))

        server_first = datetime_to_ms(flow.in_first)

        client_first = datetime_to_ms(flow.first)

        if flow.is_client_flow:
            srcip = str(flow.srcip)
            dstip = str(flow.dstip)
            sport = flow.sport
            dport = flow.dport

            flowstat_client = FlowStats(client_pkt, client_arr, client_first,
                                        server_arr, server_first, server_pkt)

            flowstat_server = FlowStats(server_pkt, server_arr, server_first,
                                        client_arr, client_first, client_pkt)
        else:
            srcip = str(flow.dstip)
            dstip = str(flow.srcip)
            sport = flow.dport
            dport = flow.sport

            flowstat_client = FlowStats(server_pkt, server_arr, server_first,
                                        client_arr, client_first, client_pkt)

            flowstat_server = FlowStats(client_pkt, client_arr, client_first,
                                        server_arr, server_first, server_pkt)

        created_server = False
        created_client = False

        # Check if the host already exist but with a different role
        srv_diff_role = False
        cli_diff_role = False

        server_pid = None
        client_pid = None

        if dstip in self.mapping_ip_host:
            srv = self.mapping_ip_host[dstip]

            if srv.startswith('c'):
                srv_diff_role = True
        else:
            srv = NetworkHandler.get_new_name(False)

        added = self.add_host(srv, dstip)
        server = self.net.get(srv)
        server_pipe = self.get_process_pipename(dstip, dport)
        if not self._is_service_running(dstip, dport):

            cmd = ("python -u server.py --addr %s --port %s --proto %s --pipe %s &"
                   % (dstip, dport, proto, server_pipe))

            logger.debug("Running command: %s", cmd)
            server_popen = server.popen(['python', '-u', 'server.py', '--addr',
                                         dstip, "--port", str(dport), "--proto",
                                         proto, "--pipe", server_pipe])
            server_pid = server_popen.pid
            if dstip not in self.mapping_server_client:
                self.mapping_server_client[dstip] = []

            if dstip not in self.mapping_involved_connection:
                self.mapping_involved_connection[dstip] = 0

            if added:
                port_srv = self.get_ofport(srv)
                server_switch = self._get_switch(False)
                logger.debug("Adding flow entry for %s to port %s on server switch", dstip,
                             port_srv)
                server_switch.dpctl('add-flow',
                                    'table=0,priority=300,dl_type=0x0800,nw_dst={},action=output:{}'.format(dstip,
                                                                                                            port_srv))
                server.setHostRoute(srcip, "-".join([srv,"eth0"]))
            time.sleep(1)
            created_server = self._is_service_running(dstip, dport)
            if created_server:
                server_pipein = os.open(server_pipe, os.O_NONBLOCK|os.O_WRONLY)
                self.write_to_pipe(pickle.dumps(flowstat_server), server_pipein)
                os.close(server_pipein)

            else:
                self.lock.release()
                return
        else:
            logger.debug("Port %s is already open on host %s", dport, dstip)
            server_pipein = os.open(server_pipe, os.O_NONBLOCK|os.O_WRONLY)
            self.write_to_pipe(pickle.dumps(flowstat_server), server_pipein)
            os.close(server_pipein)

        self.mapping_involved_connection[dstip] += 1

        # Creating client
        if srcip in self.mapping_ip_host:
            cli = self.mapping_ip_host[srcip]

            if cli.startswith('s'):
                cli_diff_role = True
        else:
            cli = NetworkHandler.get_new_name()

        added = self.add_host(cli, dstip, srcip)
        client = self.net.get(cli)
        client_pipe = self.get_process_pipename(srcip, sport)
        if not self._is_client_running(srcip, sport):
            mac = self.mapping_ip_mac[dstip]
            client.setARP(dstip, mac)
            client.setHostRoute(dstip, "-".join([cli,"eth0"]))
            logger.debug("Adding ARP entry %s for host %s to client", mac,
                         dstip)
            mac = self.mapping_ip_mac[srcip]
            server.setARP(srcip, mac)
            logger.debug("Adding ARP entry %s for host %s to server", mac,
                         srcip)

            cmd = ("python -u client.py --saddr %s --daddr %s --sport %s --dport %s " %
                   (srcip, dstip, sport, dport) +
                   "--proto %s --pipe %s &" % (proto, client_pipe))
            logger.debug("Running command: %s", cmd)
            client_popen = client.popen(['python', '-u', 'client.py', '--saddr',
                                         srcip, '--daddr', dstip, '--sport',
                                         str(sport), '--dport', str(dport), '--proto', proto,
                                         '--pipe', client_pipe])
            client_pid = client_popen.pid
            if added:
                port_cli = self.get_ofport(cli)
                client_switch = self._get_switch(True)
                logger.debug("Adding flow entry for %s to port %s on client switch ", srcip,
                             port_cli)
                client_switch.dpctl('add-flow',
                                    'table=0,priority=300,dl_type=0x0800,nw_dst={},actions=output:{}'.format(srcip,
                                                                                                         port_cli))
            time.sleep(1)
            created_client = self._is_client_running(srcip, sport)
            if created_client:
                client_pipein = os.open(client_pipe, os.O_NONBLOCK|os.O_WRONLY)
                self.write_to_pipe(pickle.dumps(flowstat_client), client_pipein)
                os.close(client_pipein)
            else:
                self.lock.release()
                return
        else:
            logger.debug("Port %s is already open on host %s", sport, srcip)
            client_pipein = os.open(client_pipe, os.O_NONBLOCK|os.O_WRONLY)
            self.write_to_pipe(pickle.dumps(flowstat_client), client_pipein)
            os.close(client_pipein)
        self.mapping_server_client[dstip].append(flow)

        if srcip not in self.mapping_involved_connection:
            self.mapping_involved_connection[srcip] = 1
        else:
            self.mapping_involved_connection[srcip] += 1

        if created_server and created_client:
            self.flow_to_pid[flow] = (client_pid, server_pid)
            logger.info("Flow %s established", flow)

        if srv_diff_role ^ cli_diff_role:
            if srv_diff_role:
                # if a client is a server now, the we add a mirror on the client
                # switch
                switch = self._get_switch(True)
                in_intf = self.mapping_host_intf[cli]
                out_intf = "%s-eth1" % (self.net.topo.cli_sw_name)
                if in_intf not in self.mirror_intf:
                    self.add_mirror(switch, in_intf, out_intf)
                    self.mirror_intf.add(in_intf)
            else:
                switch = self._get_switch(False)
                in_intf = self.mapping_host_intf[srv]
                out_intf = "%s-eth1" % (self.net.topo.srv_sw_name)
                if in_intf not in self.mirror_intf:
                    self.add_mirror(switch, in_intf, out_intf)
                    self.mirror_intf.add(in_intf)

        self.lock.release()

    def run(self, cap_cli, cap_srv, subnetwork):

        print "Starting Network Handler"
        if os.path.exists(cap_cli):
            os.remove(cap_cli)

        self.net.start()
        cmd = ("tcpdump -i %s-eth1 -n \"tcp or udp or arp\" -w %s&" %
               (self.net.topo.cli_sw_name, cap_cli))

        self.cli_sw.cmd(cmd)

        if os.path.exists(cap_srv):
            os.remove(cap_srv)

        cmd = ("tcpdump -i %s-eth1 -n \"tcp or udp or arp\" -w %s&" %
               (self.net.topo.srv_sw_name, cap_srv))
        self.srv_sw.cmd(cmd)

        self.cli_sw.dpctl("add-flow", "table=0,priority=1,dl_type=0x0800,actions=output:1")
                          

        self.srv_sw.dpctl("add-flow", "table=0,priority=1,dl_type=0x0800,actions=output:1")
                          
        time.sleep(0.5)

    def stop(self, output, cap_cli, cap_srv):

        # removing pcap at the end
        merge_out = "_".join([cap_cli[:-5], cap_srv])

        if os.path.exists(merge_out):
            os.remove(merge_out)

        if os.path.exists(output):
            os.remove(output)

        call(["mergecap", "-w", merge_out, cap_cli, cap_srv])

        if os.path.exists(merge_out):
            call(["editcap", "-D", "100", merge_out, output])

        if os.path.exists(output):
            os.remove(merge_out)

        print "Stopping Network Handler"
        self.net.stop()

def main(duration, output):

    sw_cli = "s1"
    sw_host = "s2"
    lock = threading.Lock()
    topo = GenTopo(sw_cli, sw_host)
    net = Mininet(topo)
    handler = NetworkHandler(net, lock)
    subnet = "10.0.0.0/8"

    cap_cli = "cli.pcap"

    cap_srv = "srv.pcap"

    handler.run(cap_cli, cap_srv, subnet)

    time.sleep(1)

    start_time = time.time()
    elasped_time = 0
    i = 0

    fk1 = FlowKey("10.0.0.3", "10.0.0.4", "3000", "8080", UDP)
    fk2 = FlowKey("10.0.0.5", "10.0.0.6", "3000", "8080", TCP)
    fk3 = FlowKey("10.0.0.7", "10.0.0.8", "3000", "8080", TCP)
    fk4 = FlowKey("10.0.0.9", "10.0.0.8", "3000", "8080", TCP)
    fk5 = FlowKey("10.0.0.4", "10.0.0.10", "3303", "443", TCP)
    fk6 = FlowKey("10.0.0.11", "10.0.0.9", "3000", "8080", TCP)

    f1 = Flow(fk1, 21, 1248, 16)
    f2 = Flow(fk2, 9, 152, 3)
    f3 = Flow(fk3, 42, 2642, 34)
    f4 = Flow(fk4, 60, 5049, 42)
    f5 = Flow(fk5, 25, 5000, 5)
    f6 = Flow(fk6, 24, 3424, 4) 
    flows = [f1, f2, f3, f4, f5, f6]

    cleaner = RepeatedTimer(5, handler.remove_done_host)
    while elasped_time < duration:
        if i < len(flows):
            f = flows[i]
            i += 1
            handler.establish_conn_client_server(f)
        time.sleep(0.2)
        elasped_time = time.time() - start_time
    dumpNodeConnections(net.hosts)

    if debug:
        net.pingAll()
        CLI(net)

    cleaner.stop()
    handler.stop(output, cap_cli, cap_srv)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--level", type=str, dest="level", action="store",
                        help="Logger level")
    parser.add_argument("--debug", type=str, dest="debug", action="store",
                        help="enable CLI for debug")
    parser.add_argument("--dur", type=int, dest="duration", action="store",
                        help="duration of the generation")
    parser.add_argument("--out", type=str, dest="output", action="store",
                        help="name of the pcap file")

    args = parser.parse_args()
    debug = args.debug
    duration = args.duration
    output = args.output
    logger.setLevel(args.level)

    main(duration, output)
