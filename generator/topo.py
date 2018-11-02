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

    def __init__(self, net, sw_name, **opts):
        self.net = net
        self.mapping_host_ip = {}
        self.mapping_host_intf = {}
        self.mapping_server_client = {}
        self.sw_name = sw_name
        switch = net.get(sw_name)


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
        intf = self.sw_name + "-eth%s" % (self.net.topo.intf)
        self._add_host(name, ip, port, intf)
        self.net.addHost(name)
        host = self.net.get(name)
        link = self.net.addLink(host, self.switch)
        host.setIP(client_ip) if client_ip else host.setIP(ip)
        self.switch.attach(link.intf1)
        self.net.get(sw_name).attach(intf)
        self.mapping_host_ip[name] = ip
        self.mapping_host_intf[name] = intf
        self.net.topo.intf += 1

    def remove_host(self, name):
        if name not in self.mapping_host_inft:
        self.switch.detach(intf)
        host = self.net.get(name)
        self.net.delLinkBetween(switch, host)
        self.net.delHost(host)
        self._del_host(name)

    def establish_conn_client_server(self, client, server):
        pass

        


class GenTopo(Topo):
   #
   #    C --------------Hub------------ S
   #

   def __init__(self, sw_name, **opts):

        super(GenTopo, self).__init__(**opts)

        switch = self.addSwitch(sw_name)
        client = self.addHost("cl1")
        self.addLink(client, switch)
        server = self.addHost("sr1")
        self.addLink(server, switch)
        self.intf  = 3

        
def main():

    sw_name = "s1"
    topo = GenTopo(sw_name)
    net = Mininet(topo)
    handler = NetworkHandler(net)
    net.start()
    handler.add_host(sw_name, "server", "10.0.0.4", 8080, 0 )
    handler.add_host(sw_name, "client", "10.0.0.4", 8080, 0, "10.0.0.3")
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

