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
        self.clients = []
        self.mapping_client_ip = {}
        self.servers = []
        self.mapping_server_client = {}


    def create_host(self, sw_name, name, ip, port, size, client_ip = None):
        self.net.addHost(name)
        host = self.net.get(name)
        switch = self.net.get(sw_name)
        link = self.net.addLink(host, switch)
        host.setIP(client_ip) if client_ip else host.setIP(ip)
        switch.attach(link.intf1)
        intf = sw_name + "-eth%s" % (self.net.topo.intf)
        self.net.get(sw_name).attach(intf)
        self.net.topo.intf += 1


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
    handler.create_host(sw_name, "server", "10.0.0.4", 8080, 0 )
    handler.create_host(sw_name, "client", "10.0.0.4", 8080, 0, "10.0.0.3")
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

