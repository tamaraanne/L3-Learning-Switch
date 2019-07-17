
"""Custom topology example

Two directly connected switches plus a host for each switch:
                   host   
                    |
                    |
	 host----Switch----- host
		/      \
   host --- switch --- switch --- host
            /   |       |    \
	   /    |       |     \
	 host   host    host   host
Adding the 'topos' dict with a key/value pair to generate our newly defined
topology enables one to pass in '--topo=mytopo' from the command line.
"""

from mininet.topo import Topo

class ownTopo( Topo ):
    "Simple topology example."

    def __init__( self ):
        "Create custom topo."

        # Initialize topology
        Topo.__init__( self )

        # Add hosts and switches
        leftHost_1 = self.addHost( 'h1', ip="10.0.1.2/24", defaultRoute = "via 10.0.1.1"  )
        leftHost_2 = self.addHost( 'h2', ip="10.0.1.3/24", defaultRoute = "via 10.0.1.1" )
        leftHost_3 = self.addHost( 'h3', ip="10.0.1.4/24", defaultRoute = "via 10.0.1.1" )
        leftSwitch = self.addSwitch( 's1' )
        rightSwitch = self.addSwitch( 's2' )
        middleSwitch = self.addSwitch( 's3' )
        rightHost_1 = self.addHost( 'h4', ip="10.0.2.2/24", defaultRoute = "via 10.0.2.1" )
        rightHost_2 = self.addHost( 'h5', ip="10.0.2.3/24", defaultRoute = "via 10.0.2.1" )
        rightHost_3 = self.addHost( 'h6', ip="10.0.2.4/24", defaultRoute = "via 10.0.2.1" )
        middleHost_1 = self.addHost( 'h7', ip="10.0.3.2/24", defaultRoute = "via 10.0.3.1" )
        middleHost_2 = self.addHost( 'h8', ip="10.0.3.3/24", defaultRoute = "via 10.0.3.1" )
        middleHost_3 = self.addHost( 'h9', ip="10.0.3.4/24", defaultRoute = "via 10.0.3.1" )

        # Add links
        self.addLink( leftHost_1, leftSwitch, port1 = 1, port2 = 3 )
        self.addLink( leftHost_2, leftSwitch, port1 = 1, port2 = 4  )
        self.addLink( leftHost_3, leftSwitch, port1 = 1, port2 = 5  )
        self.addLink( rightHost_1, rightSwitch, port1 = 1, port2 = 3 )
        self.addLink( rightHost_2, rightSwitch, port1 = 1, port2 = 4 )
        self.addLink( rightHost_3, rightSwitch, port1 = 1, port2 = 5 )
        self.addLink( middleHost_1, middleSwitch, port1 = 1, port2 = 3 )
        self.addLink( middleHost_2, middleSwitch, port1 = 1, port2 = 4 )
        self.addLink( middleHost_3, middleSwitch, port1 = 1, port2 = 5 )
        self.addLink( leftSwitch, rightSwitch,port1 = 1, port2 = 1 )
        self.addLink( leftSwitch, middleSwitch,port1 = 2, port2 = 1 )
        self.addLink( middleSwitch, rightSwitch,port1 = 2, port2 = 2 )


topos = { 'owntopo': ( lambda: ownTopo() ) }
                                                                                                                                                                                                          