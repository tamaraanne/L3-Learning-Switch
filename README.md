# L3-Learning-Switch

Employed MININET with a POX controller using the OpenFlow protocol to build a static layer-3 forwarder/switch. The project is divided into three parts as follows:

Part 1: Controller can be modified to act as a hub or switch. The topology is as follows:
   host ----  Hub/Switch ----- host
	            	|
            		|
      	       host
               
Part 2: Topology is modified to include another switch thereby creating two subnets as follows:
   host ----  Switch ---- Switch ----- host
	            	|
            		|
      	       host
             
Part 3: Topology is further modified to create 3 subnets with 3 hosts each as follows:
                   host   
                    |
                    |
	       host----Switch----- host
	            	/      \
     host --- switch --- switch --- host
              /   |       |    \
	           /    |       |     \
	        host   host    host   host
Firewall is put in place to block traffic on ports 54312, 12311, 21311.
 
 
Check Working of all parts:
Connectivity to all hosts is checked using the pingall command.
Check the bandwidth on the link using the iperf command.

NOTE: A more detailed README for each part is in the sub folders.
