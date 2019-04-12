#!/usr/bin/python
import argparse
import string
import sys
import os
import random
import time
import threading
import logging
from logging.handlers import RotatingFileHandler
import tempfile
import re
import cPickle as pickle
import zlib
from subprocess import Popen, call, PIPE
from subprocess import check_output
from handlers.flowDAO import FlowRequestPipeWriter
from handlers.flows import FlowLazyGen
from handlers.util import RepeatedTimer
from handlers.util import datetime_to_ms, write_message
from handlers.util import timeout_decorator
from handlers.util import MaxAttemptException
from handlers.util import TimedoutException
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.clean import cleanup
from mininet.log import setLogLevel
from mininet.cli import CLI
from mininet.node import OVSSwitch

TCP = 6
UDP = 17

protocol_version = "OpenFlow13"

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

class LocalHandler(object):

    def __init__(self):
        self.processes = []

    def _is_service_running(self, ip, port):
        logger.debug("Checking if port %s open on host %s", port, ip)
        res = check_output(["netstat", "-tulpn"])
        return ":".join([ip, port]) in res

    @timeout_decorator()
    def wait_process_creation(self, ip, port):
        return self._is_service_running(ip, port)

    def _is_client_running(self, pid, is_tcp, ip, port):
        logger.debug("Checking if client port has been bound")
        if is_tcp:
            res = check_output(["lsof", "-p", "{}".format(pid)])
            return "TCP" in res
        else:
            res = check_output(["netstat", "-tulpn"])
            logger.debug(res)
            return ":".join([ip, port]) in res

    @timeout_decorator()
    def wait_client_creation(self, pid, is_tcp, ip, port):
        return self._is_client_running(pid, is_tcp, ip, port)


    def get_process_pipename(self, ip, port, proto):
        tmpdir = tempfile.gettempdir()
        filename = os.path.join(tmpdir, "{}_{}:{}.flow".format(ip, port, proto))
        return filename

    def write_flow_to_pipe(self, threadname, pipe, message, lock):
        try:
            lock.acquire()
            writer = FlowRequestPipeWriter(pipe)
            data = zlib.compress(pickle.dumps(message))
            logger.debug("Writting %d bytes of data %s for flow %s", len(data),
                         pipe, threadname)
            writer.write(data)
        finally:
            if threadname == lock.peek():
                lock.remove_thread()
            try:
                lock.release()
            except threading.ThreadError:
                pass

    def wait_termination(self):
        for proc in self.processes:
            proc.wait()

    def establish_conn_client_server(self, flow, src_lock, dst_lock):
        proto = "tcp" if flow.proto == 6 else "udp"

        server_ps = flow.generate_server_pkts(flow.in_nb_pkt)
        server_ipt = flow.generate_server_arrs(flow.in_nb_pkt)

        client_ps = flow.generate_client_pkts(flow.nb_pkt)
        client_ipt = flow.generate_client_arrs(flow.nb_pkt)

        server_first = datetime_to_ms(flow.in_first)
        client_first = datetime_to_ms(flow.first)

        if flow.is_client_flow:
            srcip = str(flow.srcip)
            dstip = str(flow.dstip)
            sport = str(flow.sport)
            dport = str(flow.dport)
            client_lock = src_lock
            server_lock = dst_lock

            flowstat_client = FlowLazyGen(dstip, dport, flow.proto,
                                          client_first, server_first,
                                          flow.nb_pkt, flow.in_nb_pkt,
                                          client_ps, client_ipt)

            flowstat_server = FlowLazyGen(srcip, sport, flow.proto,
                                          server_first, client_first,
                                          flow.in_nb_pkt, flow.nb_pkt,
                                          server_ps, server_ipt)
        else:
            srcip = str(flow.dstip)
            dstip = str(flow.srcip)
            sport = str(flow.dport)
            dport = str(flow.sport)
            client_lock = dst_lock
            server_lock = src_lock

            flowstat_client = FlowLazyGen(srcip, sport, flow.proto,
                                          server_first, client_first,
                                          flow.in_nb_pkt, flow.nb_pkt,
                                          server_ps, server_ipt)

            flowstat_server = FlowLazyGen(dstip, dport, flow.proto,
                                          client_first, server_first,
                                          flow.nb_pkt, flow.in_nb_pkt,
                                          client_ps, client_ipt)

        server_pipe = self.get_process_pipename(dstip, dport, flow.proto)
        if not self._is_service_running(dstip, dport):
            server_proc = Popen(["python", "-u", "server.py", "--addr",
                                 dstip, "--port", dport, "--proto",
                                 proto, "--pipe", "pipe", "--pipename",
                                 server_pipe])
            try:
                self.wait_process_creation(dstip, dport)
            except MaxAttemptException as err:
                logger.debug(err.msg)
                #return
            except TimedoutException as err:
                logger.debug(err.msg)
                #return
        else:
            logger.debug("Port %s is already open on host %s", dport, dstip)

        server_lock.add_thread(str(flow))
        logger.debug(server_lock.waiting_thread)
        t_server = threading.Thread(target=self.write_flow_to_pipe,
                                    args=(str(flow), server_pipe,
                                          flowstat_server, server_lock))
        t_server.start()

        client_pipe = self.get_process_pipename(srcip, sport, flow.proto)
        if not self._is_service_running(srcip, sport):

            client_proc = Popen(["python", "-u", "client.py", "--saddr",
                                 srcip, "--daddr", dstip, "--sport",
                                 sport, "--dport", dport,
                                 "--proto", proto, "--pipe", "pipe",
                                 "--pipename", client_pipe])
            try:
                self.wait_client_creation(client_proc.pid, (proto == "tcp"),
                                          srcip, sport)
            except MaxAttemptException as err:
                logger.debug(err.msg)
                #return
            except TimedoutException as err:
                logger.debug(err.msg)
                #return
            # It all ends when clients have done
            self.processes.append(client_proc)
        else:
            logger.debug("Port %s is already open on host %s", sport, srcip)

        client_lock.add_thread(str(flow))
        t_client = threading.Thread(target=self.write_flow_to_pipe,
                                    args=(str(flow), client_pipe,
                                          flowstat_client, client_lock))
        t_client.start()

        logger.info("Flow %s established", flow)
        return t_client, t_server

class GenTopo(Topo):
   #
   #    C --------------Hub------------ S
   #

   def __init__(self, sw_a, sw_b, sw_cpt, ht_cpt,**opts):

        super(GenTopo, self).__init__(**opts)

        self.cli_sw_name = sw_a
        self.srv_sw_name = sw_b
        self.cpt_sw_name = sw_cpt
        self.cpt_ht_name = ht_cpt

        cli_sw = self.addSwitch(sw_a, cls=OVSSwitch, protocols=protocol_version, stp=True)

        cpt_sw = self.addSwitch(sw_cpt, cls=OVSSwitch,
                                protocols=protocol_version, stp=True)

        srv_sw = self.addSwitch(sw_b, cls=OVSSwitch, protocols=protocol_version, stp=True)

        self.addLink(cli_sw, srv_sw)
        self.addLink(cli_sw, cpt_sw)
        self.addLink(srv_sw, cpt_sw)

        client = self.addHost("cl1")
        self.addLink(client, cli_sw)

        server = self.addHost("sr1")
        self.addLink(server, srv_sw)

        capture = self.addHost(ht_cpt)
        self.addLink(capture, cpt_sw)

        self.cli_intf = 4
        self.srv_intf = 4
        self.capt_intf = 4


class Singleton(type):
    _instances = {}
    def __call__(cls, *args, **kwargs):
        if cls not in cls._instances:
            cls._instances[cls] = super(Singleton, cls).__call__(*args,
                                                                 **kwargs)
        return cls._instances[cls]

def of_cmd(node, *args):
    return node.cmd('ovs-ofctl', '-O', protocol_version, args[0], node, *args[1:])

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

        # process_client
        self.processes = []

        # capturing process (initialized with run)
        self.capt_popen = None

        self.cli_sw = net.get(net.topo.cli_sw_name)
        self.srv_sw = net.get(net.topo.srv_sw_name)
        self.capt_ht = net.get(net.topo.cpt_ht_name)
        self.capt_sw = net.get(net.topo.cpt_sw_name)
        self.lock = lock

        self.cli_sw_group_id = 1
        self.srv_sw_group_id = 1

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
        res = host.cmd(cmd)
        return (res != None and
                ("LISTEN" in res or
                 "ESTABLISHED" in res or
                 "CONNECTED" in res or
                 "udp" in res))

    @timeout_decorator()
    def wait_process_creation(self, ip, port):
        return self._is_service_running(ip, port)

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
        cmd = ("echo %s > /proc/sys/net/ipv4/neigh/%s-eth0/gc_stale_time" %(3600,
                                                                            name))
        host.cmd(cmd)

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

    def get_process_pipename(self, ip, port, proto):
        tmpdir = tempfile.gettempdir()
        filename = os.path.join(tmpdir, "{}_{}:{}.flow".format(ip, port, proto))
        return filename

    def get_ofport(self, name):
        intf = self.mapping_host_intf[name]
        sw_name, port = intf.split("-eth")
        return port

    def _is_client_created(self, pid, is_tcp, ip, port):
        logger.debug("Checking if client port has been bound")
        if is_tcp:
            res = check_output(["lsof", "-p", "{}".format(pid)])
            return "TCP" in res
        else:
            res = check_output(["netstat", "-tulpn"])
            logger.debug(res)
            return ":".join([ip, port]) in res

    @timeout_decorator()
    def wait_client_creation(self, pid, is_tcp, ip, port):
        return self._is_client_created(pid, is_tcp, ip, port)

    @timeout_decorator()
    def is_pipe_created(self, pipename):
        return os.path.exists(pipename)

    def write_flow_to_pipe(self, threadname, pipe, message, lock):
        lock.acquire()
        writer = FlowRequestPipeWriter(pipe)
        data = zlib.compress(pickle.dumps(message))
        logger.debug("Writting %d bytes of data to %s for flow %s", len(data),
                     pipe, threadname)
        writer.write(data)
        if threadname == lock.peek():
            lock.remove_thread()
        lock.release()

    def wait_termination(self):
        for proc in self.processes:
            proc.wait()

    def add_group_table(self, port1, port2, client=True):

        group_id = self.cli_sw_group_id if client else self.srv_sw_group_id

        if client:
            of_cmd(self.cli_sw, "add-group",
                   "group_id={},type=all,bucket=output:{},bucket=output:{}".format(
                       group_id, port1, port2))
            self.cli_sw_group_id += 1

        else:
            of_cmd(self.srv_sw, "add-group",
                   "group_id={},type=all,bucket=output:{},bucket=output:{}".format(
                       group_id, port1, port2))
            self.srv_sw_group_id += 1
        return group_id

    def establish_conn_client_server(self, flow, src_lock, dst_lock):
        self.lock.acquire()

        logger.info("Trying to establish flow: %s", flow)
        proto = "tcp" if flow.proto == 6 else "udp"

        #server_pkt, server_arr = flow.in_estim_pkt, flow.in_estim_arr
        server_pkt = flow.generate_server_pkts(flow.in_nb_pkt)
        server_arr = flow.generate_server_arrs(flow.in_nb_pkt)

        #client_pkt, client_arr = flow.estim_pkt, flow.estim_arr
        client_pkt = flow.generate_client_pkts(flow.nb_pkt)
        client_arr = flow.generate_client_arrs(flow.nb_pkt)

        server_first = datetime_to_ms(flow.in_first)

        client_first = datetime_to_ms(flow.first)

        if flow.is_client_flow:
            srcip = str(flow.srcip)
            dstip = str(flow.dstip)
            sport = flow.sport
            dport = flow.dport
            client_lock = src_lock
            server_lock = dst_lock

            flowstat_client = FlowLazyGen(dstip, dport, flow.proto, client_first,
                                          server_first, flow.nb_pkt,
                                          flow.in_nb_pkt, client_pkt,
                                          client_arr)

            flowstat_server = FlowLazyGen(srcip, sport, flow.proto, server_first,
                                          client_first, flow.in_nb_pkt,
                                          flow.nb_pkt, server_pkt,
                                          server_arr)
        else:
            srcip = str(flow.dstip)
            dstip = str(flow.srcip)
            sport = flow.dport
            dport = flow.sport
            client_lock = dst_lock
            server_lock = src_lock

            flowstat_client = FlowLazyGen(srcip, sport, flow.proto, server_first,
                                          client_first, flow.in_nb_pkt,
                                          flow.nb_pkt, server_pkt,
                                          server_arr)

            flowstat_server = FlowLazyGen(dstip, dport, flow.proto, client_first,
                                          server_first, flow.nb_pkt,
                                          flow.in_nb_pkt, client_pkt,
                                          client_arr)

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
        server_pipe = self.get_process_pipename(dstip, dport, flow.proto)
        if not os.path.exists(server_pipe):
            logger.debug("Server pipe %s does not exist", server_pipe)
            self.lock.release()
            return

        if not self._is_service_running(dstip, dport):
            cmd = ("python -u server.py --addr %s --port %s --proto %s --pipe pipe --pipename %s"
                   % (dstip, dport, proto, server_pipe))

            logger.debug("Running command: %s", cmd)
            server_popen = server.popen(["python", "-u", "server.py", "--addr",
                                         dstip, "--port", str(dport), "--proto",
                                         proto, "--pipe", "pipe", "--pipename", server_pipe])
            if dstip not in self.mapping_server_client:
                self.mapping_server_client[dstip] = []

            if dstip not in self.mapping_involved_connection:
                self.mapping_involved_connection[dstip] = 0

            if added:
                port_srv = self.get_ofport(srv)
                server_switch = self._get_switch(False)
                logger.debug("Adding flow entry for %s to port %s on server switch", dstip,
                             port_srv)
                of_cmd(server_switch, 'add-flow',
                       'table=0,priority=300,in_port=1,dl_type=0x0800,nw_dst={},actions=output:{}'.format(
                           dstip, port_srv))

                gid = self.add_group_table(2, port_srv)
                of_cmd(server_switch, 'add-flow',
                       'table=0,priority=300,dl_type=0x0800,nw_dst={},actions=group:{}'.format(
                           dstip, gid))
                server.setHostRoute(srcip, "-".join([srv, "eth0"]))

            try:
                self.wait_process_creation(dstip, dport)
            except MaxAttemptException as err:
                logger.debug(err.msg)
                self.lock.release()
            except TimedoutException as err:
                logger.debug(err.msg)
                self.lock.release()

        else:
            logger.debug("Port %s is already open on host %s", dport, dstip)
        server_lock.add_thread(str(flow))
        t_server = threading.Thread(target=self.write_flow_to_pipe,
                                    args=(str(flow), server_pipe, flowstat_server,
                                          server_lock))
        t_server.start()

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
        client_pipe = self.get_process_pipename(srcip, sport, flow.proto)
        if not os.path.exists(client_pipe):
            logger.debug("Client pipe %s does not exist", client_pipe)
            self.lock.release()
            return

        if not self._is_client_running(srcip, sport):
            mac = self.mapping_ip_mac[dstip]
            client.setARP(dstip, mac)
            client.setHostRoute(dstip, "-".join([cli, "eth0"]))
            logger.debug("Adding ARP entry %s for host %s to client", mac,
                         dstip)
            mac = self.mapping_ip_mac[srcip]
            server.setARP(srcip, mac)
            logger.debug("Adding ARP entry %s for host %s to server", mac,
                         srcip)

            cmd = ("python -u client.py --saddr %s --daddr %s --sport %s --dport %s" %
                   (srcip, dstip, sport, dport) +
                   "--proto %s --pipe pipe --pipename %s &" % (proto, client_pipe))
            logger.debug("Running command: %s", cmd)
            client_popen = client.popen(["python", "-u", "client.py", "--saddr",
                                         srcip, "--daddr", dstip, "--sport",
                                         str(sport), "--dport", str(dport), "--proto", proto,
                                         "--pipe", "pipe", "--pipename", client_pipe])
            self.processes.append(client_popen)
            client_pid = client_popen.pid
            if added:
                port_cli = self.get_ofport(cli)
                client_switch = self._get_switch(True)
                logger.debug("Adding flow entry for %s to port %s on client switch ", srcip,
                             port_cli)
                of_cmd(client_switch, 'add-flow',
                       'table=0,priority=300,in_port=1,dl_type=0x0800,nw_dst={},actions=output:{}'.format(
                           srcip, port_cli))

                gid = self.add_group_table(2, port_cli)

                of_cmd(client_switch, 'add-flow',
                       'table=0,priority=300,dl_type=0x0800,nw_dst={},actions=group:{}'.format(
                           srcip, gid))
            try:
                self.wait_client_creation(client_pid, (proto == "tcp"), srcip,
                                          str(sport))
            except MaxAttemptException as err:
                logger.debug(err.msg)
                self.lock.release()
            except TimedoutException as err:
                logger.debug(err.msg)
                self.lock.release()
        else:
            logger.debug("Port %s is already open on host %s", sport, srcip)
        t_client = threading.Thread(target=self.write_flow_to_pipe,
                                    args=(str(flow), client_pipe, flowstat_client,
                                          client_lock))
        client_lock.add_thread(str(flow))
        t_client.start()
        self.mapping_server_client[dstip].append(flow)

        if srcip not in self.mapping_involved_connection:
            self.mapping_involved_connection[srcip] = 1
        else:
            self.mapping_involved_connection[srcip] += 1

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

        logger.info("Flow %s established", flow)
        self.lock.release()
        return t_client, t_server

    def run(self, cap_name, subnetwork):

        print "Starting Network Handler"

        self.net.start()
        if os.path.exists(cap_name):
            os.remove(cap_name)

        cmd = ("tcpdump -i %s-eth0 -n \"tcp or udp or arp or icmp\" -w %s&" %
               (self.net.topo.cpt_ht_name, cap_name))

        self.capt_popen = self.capt_ht.popen(["tcpdump", "-i",
                                              "{}-eth0".format(self.net.topo.cpt_ht_name),
                                              "-n",
                                              "\"tcp or udp or arp or icmp\"",
                                              "-w", "{}".format(cap_name)],
                                             stdout=PIPE, shell=True)

        #creating group table in switch to mirror packet
        gid = self.add_group_table(1, 2, client=True)

        of_cmd(self.cli_sw, 'add-flow',
               "table=0,priority=1,dl_type=0x0800,actions=group:{}".format(gid))

        gid = self.add_group_table(1, 2, client=False)

        #apply group based on flow matching
        of_cmd(self.srv_sw, 'add-flow',
               "table=0,priority=1,dl_type=0x0800,actions=group:{}".format(gid))

        of_cmd(self.capt_sw, 'add-flow',
               "table=0,priority=1,dl_type=0x0800,actions=output:3")
        time.sleep(0.5)

    def ping_test_setup(self):

        of_cmd(self.cli_sw, 'add-flow',
               "table=0,priority=20,dl_type=0x0800,in_port=1,nw_dst=10.0.0.1,actions=output:3")

        gid = self.add_group_table(3, 2)

        of_cmd(self.cli_sw, 'add-flow',
               "table=0,priority=20,dl_type=0x0800,nw_dst=10.0.0.1,actions=group:{}".format(gid))

        of_cmd(self.cli_sw, 'add-flow',
               "table=0,priority=20,dl_type=0x0800,in_port=1,nw_dst=10.0.0.3,actions=output:4")

        gid = self.add_group_table(4, 2)

        of_cmd(self.cli_sw, 'add-flow',
               "table=0,priority=20,dl_type=0x0800,nw_dst=10.0.0.3,actions=group:{}".format(gid))


        of_cmd(self.srv_sw, 'add-flow',
               "table=0,priority=20,dl_type=0x0800,in_port=1,nw_dst=10.0.0.2,actions=output:3")

        gid = self.add_group_table(3, 2, client=False)

        of_cmd(self.srv_sw, 'add-flow',
               "table=0,priority=20,dl_type=0x0800,nw_dst=10.0.0.2,actions=group:{}".format(gid))

        of_cmd(self.srv_sw, 'add-flow',
               "table=0,priority=20,dl_type=0x0800,in_port=1,nw_dst=10.0.0.4,actions=output:4")

        gid = self.add_group_table(4, 2, client=False)

        of_cmd(self.srv_sw, 'add-flow',
               "table=0,priority=20,dl_type=0x0800,nw_dst=10.0.0.4,actions=group:{}".format(gid))


    def stop(self, output):

        # removing pcap at the end
        #merge_out = "_".join([cap_cli[:-5], cap_srv])

        #if os.path.exists(merge_out):
        #    os.remove(merge_out)

        #if os.path.exists(output):
        #    os.remove(output)

        #call(["mergecap", "-w", merge_out, cap_cli, cap_srv])

        #if os.path.exists(merge_out):
        #    call(["editcap", "-D", "100", merge_out, output])

        #if os.path.exists(output):
        #    os.remove(merge_out)
        #    os.remove(cap_cli)
        #    os.remove(cap_srv)

        print "Stopping Network Handler"
        #self.capt_popen.terminate()
        time.sleep(1.5)
        self.net.stop()

def main(output):

    sw_cli = "s1"
    sw_srv = "s2"
    sw_capt = "s3"
    ht_capt = "ids"
    lock = threading.RLock()
    topo = GenTopo(sw_cli, sw_srv, sw_capt, ht_capt)

    client_b = topo.addHost("cl2")
    server_b = topo.addHost("sr2")

    topo.addLink(sw_cli, client_b)
    topo.addLink(sw_srv, server_b)

    net = Mininet(topo)
    handler = NetworkHandler(net, lock)
    subnet = "10.0.0.0/8"

    client = net.get("cl1")
    server = net.get("sr1")
    client_b = net.get("cl2")
    server_b = net.get("sr2")

    cl_ip = "10.0.0.1"
    cl_mac = "00:00:00:00:00:01"

    client.setIP(cl_ip)
    client.setMAC(cl_mac)

    sr_ip = "10.0.0.2"
    sr_mac = "00:00:00:00:00:02"

    server.setIP(sr_ip)
    server.setMAC(sr_mac)

    cl_b_ip = "10.0.0.3"
    cl_b_mac = "00:00:00:00:00:03"

    client_b.setIP(cl_b_ip)
    client_b.setMAC(cl_b_mac)

    sr_b_ip = "10.0.0.4"
    sr_b_mac = "00:00:00:00:00:04"

    server_b.setIP(sr_b_ip)
    server_b.setMAC(sr_b_mac)

    client.setARP(sr_ip, sr_mac)
    client.setARP(sr_b_ip, sr_b_mac)
    client.setARP(cl_b_ip, cl_b_mac)

    server.setARP(cl_ip, cl_mac)
    server.setARP(cl_b_ip, cl_b_mac)
    server.setARP(sr_b_ip, sr_b_mac)

    client_b.setARP(sr_ip, sr_mac)
    client_b.setARP(sr_b_ip, sr_b_mac)
    client_b.setARP(cl_ip, cl_mac)

    server_b.setARP(sr_ip, sr_mac)
    server_b.setARP(cl_ip, cl_mac)
    server_b.setARP(cl_b_ip, cl_b_mac)

    handler.run(output, subnet)

    handler.ping_test_setup()
    time.sleep(1)

    CLI(net)

    handler.stop(output)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--level", type=str, dest="level", action="store",
                        help="Logger level")
    parser.add_argument("--debug", type=str, dest="debug", action="store",
                        help="enable CLI for debug")
    parser.add_argument("--out", type=str, dest="output", action="store",
                        help="name of the pcap file")

    args = parser.parse_args()
    debug = args.debug
    output = args.output
    logger.setLevel(args.level)

    try:
        main(output)
    finally:
        cleanup()
