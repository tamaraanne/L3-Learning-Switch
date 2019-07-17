=========================================================================================================
					README for part 1 of EE555 OpenFlow Project
=========================================================================================================
Contributors:
Manjunath Chole
Tamara Fernandes

==========================================================================================================
						Files submitted
=========================================================================================================
1) mytopo.py
2) of_tutorial.py
3) router.py

=========================================================================================================
						How to Verify
=========================================================================================================
In the file "of_tutorial.py" and definition "_handle_PacketIn",
	1) To make Controller behave like a Hub 
		Uncomment self.act_like_hub(packet, packet_in)
		Comment self.act_like_switch(packet, packet_in)
		
		
	2) To make Controller behave like a Switch
		Comment self.act_like_hub(packet, packet_in)
		UnComment self.act_like_switch(packet, packet_in)		
					
	
For Hub and Switch, 
	Use the below command for Topology:
	sudo mn --topo single,3 --mac --switch ovsk --controller remote

	To start the controller copy the of_tutorial.py file into /home/mininet/pox/pox/misc/ and then run:
                 cd pox
		./pox.py log.level  --DEBUG misc.of_tutorial

For Router, 
	First Copy mytopo.py to /home/mininet/custom and then use the below command for Custom Topology:
		cd mininet/custom	
		sudo mn --custom mytopo.py --topo mytopo --mac --controller=remote,ip=127.0.0.1

 	To start controller copy router.py file into /home/pox/pox/forwarding:
		cd pox 
    		$ ./pox.py log.level --DEBUG pox.forwarding.router  misc.full_payload


NOTE:
If you come across an error which looks like below while running the POX controller, please run "sudo fuser -k 6633/tcp" first
ERROR:openflow.of_01:Error 98 while binding socket: Address already in use
ERROR:openflow.of_01: You may have another controller running.
ERROR:openflow.of_01: Use openflow.of_01 --port=<port> to run POX on another port.


=====================================================================================================================================
						Reference
=====================================================================================================================================
Code snippet for ICMP packets is taken from pong.py for constructing ICMP replies from /home/mininet/pox/pox/proto/
Code snippet for pv4 instance and arp instance is taken from l3_learning.py for constructing ICMP replies from /home/mininet/pox/pox/forwarding/
Code snippet from https://noxrepo.github.io/pox-doc/html/