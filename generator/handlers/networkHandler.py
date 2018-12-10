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
from subprocess import call
from logging.handlers import RotatingFileHandler
from flows import Flow
from flows import FlowKey
from util import RepeatedTimer
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.util import irange
from mininet.util import dumpNodeConnections
from mininet.log import setLogLevel
from mininet.cli import CLI

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

        cli_sw = self.addSwitch(sw_a)
        srv_sw = self.addSwitch(sw_b)
        self.addLink(cli_sw, srv_sw)

        client = self.addHost("cl1")
        self.addLink(client, cli_sw)

        server = self.addHost("sr1")
        self.addLink(server, srv_sw)

        self.cli_intf = 3
        self.srv_intf = 3


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

        # keep track of existing connection
        self.mapping_server_client = {}

        # The number of connection for each
        self.mapping_involved_connection = {}

        self.current_mac = 1

        # mac address for each host
        self.mapping_ip_mac = {}

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
        filename = tmpdir + "/" + ip + "_" + str(port) + ".tmp"
        logger.debug("Checking client %s on port %s", ip, port)
        res = os.path.exists(filename)
        logger.debug("Result: %s", res )
        return res
                 

    def remove_done_host(self):
        self.lock.acquire()
        to_remove = []
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

        logger.info("Server done: %s", to_remove)
        try:
            for server in to_remove:
                name = self.mapping_ip_host[server]
                self.remove_host(server, False)
                logger.info("Removing Server %s with Ip %s",
                             name, server)
                self.mapping_server_client.pop(server, None)
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
            logger.debug("Setting ARP %s for host %s ", mac, p_ip)
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

    def add_mirror(self, switch, in_intf, out_intf):

        cmd = "tc qdisc add dev %s ingress;:" % in_intf
        switch.cmd(cmd)

        mir_1 = ("tc filter add dev %s parent ffff: protocol ip  u32 match" %
                 in_intf)
        mir_2 = "u8 0 0 action mirred egress mirror dev %s;:" % out_intf
        switch.cmd(mir_1 + " " + mir_2)


        cmd = "tc qdisc add dev %s handle 1: root prio;:" % in_intf
        switch.cmd(cmd)
        mir_1 = ("tc filter add dev %s parent 1: protocol ip u32 match" %
                 in_intf)
        mir_2 = "u8 0 0 action mirred egress mirror dev %s;:" % out_intf
        switch.cmd(mir_1 + " " + mir_2)


    def del_mirror(self, switch, in_intf):
        cmd = "tc qdisc del dev %s ingress;:" % in_intf
        switch.cmd(cmd)

    def remove_host(self, ip, is_client=True):
        try:
            name = self.mapping_ip_host[ip]
            intf = self.mapping_host_intf[name]
            switch = self._get_switch(is_client)
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


    def establish_conn_client_server(self, flow):

        self.lock.acquire()

        logger.info("Trying to establish flow: %s", flow)
        proto = "tcp" if flow.proto == 6 else "udp"

        # Creating server
        srcip = str(flow.srcip)
        dstip = str(flow.dstip)

        created_server = False
        created_client = False

        # Check if the host already exist but with a different role
        srv_diff_role = False
        cli_diff_role = False

        if dstip in self.mapping_ip_host:
            srv = self.mapping_ip_host[dstip]

            if srv.startswith('c'):
                srv_diff_role = True
        else:
            srv = NetworkHandler.get_new_name(False)

        self.add_host(srv, dstip)
        server = self.net.get(srv)
        if not self._is_service_running(dstip, flow.dport):
            cmd = ("python3 -u server.py --addr %s --port %s --proto %s&" %
                   (dstip, flow.dport, proto))
            logger.debug("Running command: %s", cmd)
            server.cmd(cmd)
            if dstip not in self.mapping_server_client:
                self.mapping_server_client[dstip] = []

            time.sleep(0.15)
            created_server = self._is_service_running(dstip, flow.dport)
            if not created_server:
                self.lock.release()
                return
        else:
            logger.debug("Port %s is already open on host %s", flow.dport, dstip)

        if dstip not in self.mapping_involved_connection:
            self.mapping_involved_connection[dstip] = 1
        else:
            self.mapping_involved_connection[dstip] += 1

        # Creating client
        if srcip in self.mapping_ip_host:
            cli = self.mapping_ip_host[srcip]

            if cli.startswith('s'):
                cli_diff_role = True
        else:
            cli = NetworkHandler.get_new_name()

        self.add_host(cli, dstip, srcip)
        client = self.net.get(cli)
        if not self._is_client_running(srcip, flow.sport):
            mac = self.mapping_ip_mac[dstip]
            client.setARP(dstip, mac)
            logger.debug("Adding ARP entry %s for host %s to client", mac,
                         dstip)

            cmd = ("python3 -u client.py --saddr %s --daddr %s --sport %s --dport %s " %
                   (srcip, dstip, flow.sport, flow.dport) +
                   "--proto %s --dur %s --size %s --nbr %s &" %
                   (proto, flow.dur, flow.size, flow.nb_pkt))
            logger.debug("Running command: %s", cmd)
            client.cmd(cmd)
            #time.sleep(0.2)
            created_client = self._is_client_running(srcip, flow.sport)
        else:
            logger.debug("Port %s is already open on host %s", flow.sport,
                         srcip)

        self.mapping_server_client[dstip].append(flow)

        if srcip not in self.mapping_involved_connection:
            self.mapping_involved_connection[srcip] = 1
        else:
            self.mapping_involved_connection[srcip] += 1

        if created_server and created_client:
            logger.info("Flow %s established", flow)

        if srv_diff_role ^ cli_diff_role:
            if srv_diff_role:
                # if a client is a server now, the we add a mirror on the client
                # switch
                switch = self._get_switch(True)
                in_intf = self.mapping_host_intf[cli]
                out_intf = "%s-eth1" % (self.net.topo.cli_sw_name)
                self.add_mirror(switch, in_intf, out_intf)
            else:
                switch = self._get_switch(False)
                in_intf = self.mapping_host_intf[srv]
                out_intf = "%s-eth1" % (self.net.topo.srv_sw_name)
                self.add_mirror(switch, in_intf, out_intf)

        logger.debug("Involved connection: %s", self.mapping_involved_connection)

        self.lock.release()

    def run(self, cap_cli, cap_srv, subnetwork):

        print "Starting Network Handler"
        if os.path.exists(cap_cli):
            os.remove(cap_cli)

        self.net.start()
        cmd = ("tcpdump -i %s-eth1 -n \"tcp or udp or arp\" -w %s&" %
               (self.net.topo.cli_sw_name, cap_cli))

        #cmd = ("tcpdump -i any -n \'net %s and (tcp or udp or arp)\' -w %s&" %
        #       (subnetwork, capture))
        self.cli_sw.cmd(cmd)

        if os.path.exists(cap_srv):
            os.remove(cap_srv)

        cmd = ("tcpdump -i %s-eth1 -n \"tcp or udp or arp\" -w %s&" %
               (self.net.topo.srv_sw_name, cap_srv))
        self.srv_sw.cmd(cmd)

        time.sleep(0.5)
        #print output

    def stop(self, output, cap_cli, cap_srv):

        # removing pcap at the end
        merge_out = "_".join([cap_cli[:-5], cap_srv])

        if os.path.exists(merge_out):
            os.remove(merge_out)

        if os.path.exists(output):
            os.remove(output)

        call(["mergecap", "-w", merge_out, cap_cli, cap_srv])

        if os.path.exists(merge_out):
            os.remove(cap_cli)
            os.remove(cap_srv)
            call(["editcap", "-d", merge_out, output])

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

    f1 = Flow(fk1, 21, 1248, 16)
    f2 = Flow(fk2, 9, 152, 3)
    f3 = Flow(fk3, 42, 2642, 34)
    f4 = Flow(fk4, 60, 5049, 42)
    f5 = Flow(fk5, 25, 5000, 5)
    flows = [f1, f2, f3, f4, f5]

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
