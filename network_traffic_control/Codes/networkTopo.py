#!/usr/bin/python

from mininet.net import Mininet
from mininet.cli import CLI
from mininet.node import Host
from mininet.node import OVSKernelSwitch
from mininet.log import setLogLevel, info
from mininet.node import RemoteController
from mininet.term import makeTerm


def myNetwork():
    net = Mininet(topo=None, autoSetMacs=True, build=False, ipBase='10.0.1.0/24')

    h1 = net.addHost(name='Client', cls=Host, defaultRoute=None)
    h2 = net.addHost(name='Server1', cls=Host, defaultRoute=None)
    h3 = net.addHost(name='Server2', cls=Host, defaultRoute=None)
    s1 = net.addSwitch(name='s1', cls=OVSKernelSwitch, failMode='secure')
    c1 = net.addController(name='Controller', controller=RemoteController)

    net.build()

    net.addLink(s1, h3)
    net.addLink(h1, s1)
    net.addLink(s1, h2)

    h1.setMAC(intf='Client-eth0', mac='00:00:00:00:00:03')
    h2.setMAC(intf='Server1-eth0', mac='00:00:00:00:00:01')
    h3.setMAC(intf='Server2-eth0', mac='00:00:00:00:00:02')
    h1.setIP(intf='Client-eth0', ip='10.0.1.5/24')
    h2.setIP(intf='Server1-eth0', ip='10.0.1.2/24')
    h3.setIP(intf='Server2-eth0', ip='10.0.1.3/24')

    net.start()

    net.terms += makeTerm(c1)
    net.terms += makeTerm(s1)
    net.terms += makeTerm(h1)
    net.terms += makeTerm(h2)
    net.terms += makeTerm(h3)

    CLI(net)
    net.stop()


if __name__ == '__main__':
    setLogLevel('info')
    myNetwork()
