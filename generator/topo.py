#!/usr/bin/python


from mininet.topo import Topo
from mininet.net import Mininet
from mininet.util import irange
from mininet.util import dumpNodeConnections
from mininet.log import setLogLevel
from mininet.cli import CLI


class NetworkHandler(object):

    """
        This class manage the network by connecting to mininet
    """

    def __init__(self, net, **opts):
        self.net = net
        self.mapping_host_ip = {}
        self.mapping_host_intf = {}
        self.mapping_server_client = {}
        self.cli_sw = net.get(net.topo.cli_sw_name)
        self.host_sw = net.get(net.topo.host_sw_name)


    def _add_host(self, name, ip, port, intf):
        if name in self.mapping_host_ip or name in self.mapping_host_intf:
            raise ValueError("Name %s already exist" % name)
        self.mapping_host_ip[name] = ip
        self.mapping_host_intf[name] = intf

    def _del_host(self, name):
        if name not in self.mapping_host_inft or name not in self.mapping_host_ip:
            raise KeyError("Name %s does not exist" % name)

        self.mapping_host_ip.pop(name, None)
        self.mapping_host_intf.pop(name, None)


    def add_host(self, name, ip, port, size, client_ip = None):
        if client_ip:
            intf = self.net.topo.cli_sw_name + "-eth%s" % (self.net.topo.cli_intf)
        else:
            intf = self.net.topo.host_sw_name + "-eth%s" % (self.net.topo.host_intf)

        self._add_host(name, ip, port, intf)
        self.net.addHost(name)
        host = self.net.get(name)
        switch = self.cli_sw if client_ip else self.host_sw
        link = self.net.addLink(host, switch)
        host.setIP(client_ip) if client_ip else host.setIP(ip)
        switch.attach(link.intf1)
        switch.attach(intf)
        self.mapping_host_ip[name] = ip
        self.mapping_host_intf[name] = intf
        if client_ip:
            self.net.topo.cli_intf += 1
        else:
            self.net.topo.host_intf += 1

    def remove_host(self, name):
        if name not in self.mapping_host_inft:
            self.switch.detach(intf)
            host = self.net.get(name)
            self.net.delLinkBetween(switch, host)
            self.net.delHost(host)
            self._del_host(name)

    def establish_conn_client_server(self, client, server):
        #ADD to dictionary
        pass

        


class GenTopo(Topo):
   #
   #    C --------------Hub------------ S
   #

   def __init__(self, sw_a, sw_b, **opts):

        super(GenTopo, self).__init__(**opts)

        self.cli_sw_name = sw_a
        self.host_sw_name = sw_b

        cli_sw = self.addSwitch(sw_a)
        host_sw = self.addSwitch(sw_b)
        self.addLink(cli_sw, host_sw)

        client = self.addHost("cl1")
        self.addLink(client, cli_sw)

        server = self.addHost("sr1")
        self.addLink(server, host_sw)

        self.cli_intf  = 3
        self.host_intf  = 3

        
def main():

    sw_cli = "s1"
    sw_host = "s2"
    topo = GenTopo(sw_cli, sw_host)
    net = Mininet(topo)
    handler = NetworkHandler(net)
    net.start()
    handler.add_host("server", "10.0.0.4", 8080, 0 )
    handler.add_host("client", "10.0.0.4", 8080, 0, "10.0.0.3")
    print "Dumping host connections"
    dumpNodeConnections(net.hosts)
    print "Testing network connectivity"
    net.pingAll()
    print "Ready !"
    CLI(net)
    net.stop()

if __name__ == "__main__":
    setLogLevel("info")
    main()

