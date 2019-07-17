"""Custom topology example

Two directly connected switches plus a host for each switch:

   host --- switch --- switch --- host
		|
		|
	       host
Adding the 'topos' dict with a key/value pair to generate our newly defined
topology enables one to pass in '--topo=mytopo' from the command line.
"""

from mininet.topo import Topo

class adTopo( Topo ):
    "Simple topology example."

    def __init__( self ):
        "Create custom topo."

        # Initialize topology
        Topo.__init__( self )

        # Add hosts and switches
        leftHost_1 = self.addHost( 'h3', ip="10.0.1.2/24", defaultRoute = "via 10.0.1.1"  )
        leftHost_2 = self.addHost( 'h4', ip="10.0.1.3/24", defaultRoute = "via 10.0.1.1" )
        leftSwitch = self.addSwitch( 's1' )
	rightSwitch = self.addSwitch( 's2' )
	rightHost = self.addHost( 'h5', ip="10.0.2.2/24", defaultRoute = "via 10.0.2.1" )


        # Add links
        self.addLink( leftHost_1, leftSwitch, port1 = 1, port2 = 2 )
        self.addLink( leftHost_2, leftSwitch, port1 = 1, port2 = 3  )
        self.addLink( rightHost, rightSwitch, port1 = 1, port2 = 2 )
        self.addLink( leftSwitch, rightSwitch, port1 = 1, port2 = 1 )


topos = { 'adtopo': ( lambda: adTopo() ) }