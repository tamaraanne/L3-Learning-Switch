=================================================================================================================================================
								README for part 2
==================================================================================================================================================
Contributors:
Manjunath Chole
Tamara Fernandes
===================================================================================================================================================
								Files submitted
====================================================================================================================================================
1) adtopo.py
2) advance.py

====================================================================================================================================================
								How to Verify
====================================================================================================================================================
		
	
To Verify 
>> Attempts to send from a host to an unknown address range should yield an ICMP destination unreachable message.
	A) ping an unreachable host like 10.99.99.99
>> Packets sent to hosts on a known address range should have their MAC dst field changed to that of the next-hop router.
	A) run TCPdump on one xterm host and ping that host from another or send UDP/TCP packets using Iperf
>> The router should be pingable, and should generate an ICMP echo reply in response to an ICMP echo request.
	A)ping H4->H5
>> All hosts must be connected to each other. This can be verified using 'pingall'.
	A) pingall from $mininet


For Router:
	First Copy adtopo.py to /home/mininet/custom and then use the below command for Custom Topology:
		cd mininet/custom	
		sudo mn --custom adtopo.py --topo adtopo --mac --controller=remote,ip=127.0.0.1

	To start controller copy advance.py file into /home/pox/pox/forwarding:
		cd pox 
    		$ ./pox.py log.level --DEBUG pox.forwarding.advance misc.full_payload



NOTE:
If you come across an error which looks like below while running the POX controller, please run "sudo fuser -k 6633/tcp" first
ERROR:openflow.of_01:Error 98 while binding socket: Address already in use
ERROR:openflow.of_01: You may have another controller running.
ERROR:openflow.of_01: Use openflow.of_01 --port=<port> to run POX on another port.
============================================================================================================================================================
								Reference
==============================================================================================================================================================
Code snippet for ICMP packets is taken from pong.py for constructing ICMP replies from /home/mininet/pox/pox/proto/
Code snippet for ipv4 instance and arp instance is taken from l3_learning.py for constructing ICMP replies from /home/mininet/pox/pox/forwarding/

