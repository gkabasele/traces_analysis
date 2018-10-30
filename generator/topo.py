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


    def create_server(self, name, ip, port, size):
        pass

    def create_client(self, name, ip, port, duration):
        pass



class HubTopo(Topo):
   #
   #    C --------------Hub------------ S
   #
   #

   def __init__(self, clients=1, servers=1, **opts):

        super(HubTopo, self).__init__(**opts)

        switch = self.addSwitch("s1")

        for i in xrange(1, clients):
            client = self.addHost('client-{}'.format(i))
            self.addLink(client, switch)

        for i in xrange(1, servers):
            server = self.addHost('server-{}'.format(i))
            self.addLink(server, switch)

def simpleTest():

    topo = HubTopo(2,2)
    net = Mininet(topo)
    net.start()
    print "Dumping host connections"
    dumpNodeConnections(net.hosts)
    print "Testing network connectivity"
    net.pingAll()
    print "Ready !"
    CLI(net)
    net.stop()

if __name__ == "__main__":
    setLogLevel("info")
    simpleTest()

