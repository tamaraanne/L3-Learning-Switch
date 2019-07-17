

#Copyright 2012-2013 James McCauley
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
A stupid L3 switch

For each switch:
1) Keep a table that maps IP addresses to MAC addresses and switch ports.
   Stock this table using information from ARP and IP packets.
2) When you see an ARP query, try to answer it using information in the table
   from step 1.  If the info in the table is old, just flood the query.
3) Flood all other ARPs.
4) When you see an IP packet, if you know the destination port (because it's
   in the table from step 1), install a flow for it.
"""

from pox.core import core
import pox
log = core.getLogger()

from pox.lib.packet.ethernet import ethernet, ETHER_BROADCAST
from pox.lib.packet.ipv4 import ipv4
from pox.lib.packet.arp import arp
from pox.lib.addresses import IPAddr, EthAddr
from pox.lib.packet.icmp import icmp
from pox.lib.util import str_to_bool, dpid_to_str
from pox.lib.recoco import Timer
import pox.lib.packet as pkt

import pox.openflow.libopenflow_01 as of
import pox.openflow.libopenflow_01 as of

from pox.lib.revent import *

import time
import struct

# Timeout for flows
FLOW_IDLE_TIMEOUT = 10

# Timeout for ARP entries
ARP_TIMEOUT = 60 * 5

# Maximum number of packet to buffer on a switch for an unknown IP
MAX_BUFFERED_PER_IP = 5

# Maximum time to hang on to a buffer for an unknown IP in seconds
MAX_BUFFER_TIME = 5

blocking_port = set()

class Entry (object):
  """
  Not strictly an ARP entry.
  We use the port to determine which port to forward traffic out of.
  We use the MAC to answer ARP replies.
  We use the timeout so that if an entry is older than ARP_TIMEOUT, we
   flood the ARP request rather than try to answer it ourselves.
  """
  def __init__ (self, port, mac):
    self.timeout = time.time() + ARP_TIMEOUT
    self.port = port
    self.mac = mac

  def __eq__ (self, other):
    if type(other) == tuple:
      return (self.port,self.mac)==other
    else:
      return (self.port,self.mac)==(other.port,other.mac)
  def __ne__ (self, other):
    return not self.__eq__(other)

  def isExpired (self):
    if self.port == of.OFPP_NONE: return False
    return time.time() > self.timeout


def dpid_to_mac (dpid):
  return EthAddr("%012x" % (dpid & 0xffFFffFFffFF,))

def firewall (event):
  
  port = event.parsed.find('tcp')
  if port: 
    if port.srcport in blocking_port or port.dstport in blocking_port:
      core.getLogger("WARNING").debug("Blocked TCP packets on port %s",port.dstport)
      event.halt = True
  else:
    return


class l3_switch (EventMixin):
  def __init__ (self, fakeways = [], arp_for_unknowns = False):
    # These are "fake gateways" -- we'll answer ARPs for them with MAC
    # of the switch they're connected to.
    self.fakeways = set(fakeways)

    # If this is true and we see a packet for an unknown
    # host, we'll ARP for it.
    self.arp_for_unknowns = arp_for_unknowns

    # (dpid,IP) -> expire_time
    # We use this to keep from spamming ARPs
                                                                                                                                                                                        
    self.outstanding_arps = {}

    # (dpid,IP) -> [(expire_time,buffer_id,in_port), ...]
    # These are buffers we've gotten at this datapath for this IP which
    # we can't deliver because we don't know where they go.
    self.lost_buffers = {}

    self.connections = {}

    # For each switch, we map IP addresses to Entries
    self.arpTable = {}

    self.routing = {}
    # This timer handles expiring stuff
    self._expire_timer = Timer(5, self._handle_expiration, recurring=True)

    self.listenTo(core)

  def _handle_expiration (self):
    # Called by a timer so that we can remove old items.
    empty = []
    for k,v in self.lost_buffers.iteritems():
      dpid,ip = k

      for item in list(v):
        expires_at,buffer_id,in_port = item
        if expires_at < time.time():
          # This packet is old.  Tell this switch to drop it.
          v.remove(item)
          po = of.ofp_packet_out(buffer_id = buffer_id, in_port = in_port)
          core.openflow.sendToDPID(dpid, po)
      if len(v) == 0: empty.append(k)

    # Remove empty buffer bins
    for k in empty:
      del self.lost_buffers[k]

  def _send_lost_buffers (self, dpid, ipaddr, macaddr, port):
    """
    We may have "lost" buffers -- packets we got but didn't know
    where to send at the time.  We may know now.  Try and see.
    """
    if (dpid,ipaddr) in self.lost_buffers:
      # Yup!
      bucket = self.lost_buffers[(dpid,ipaddr)]
      del self.lost_buffers[(dpid,ipaddr)]
      log.debug("Sending %i buffered packets to %s from %s"
                % (len(bucket),ipaddr,dpid_to_str(dpid)))
      for _,buffer_id,in_port in bucket:
        po = of.ofp_packet_out(buffer_id=buffer_id,in_port=in_port)
        po.actions.append(of.ofp_action_dl_addr.set_dst(macaddr))
        po.actions.append(of.ofp_action_output(port = port))
        core.openflow.sendToDPID(dpid, po)




  def icmp_message(self, dpid, p, srcip, dstip, icmp_type,event):
    p_icmp = icmp()
    p_icmp.type = icmp_type
    if icmp_type == pkt.TYPE_ECHO_REPLY:
      p_icmp.payload = p.find('icmp').payload
    elif icmp_type == pkt.TYPE_DEST_UNREACH:
            #print dir(p.next)
      orig_ip = p.find('ipv4')
      d = orig_ip.pack()
      d = d[:orig_ip.hl * 4 + 8]
      d = struct.pack("!HH", 0, 0) + d # network, unsigned short, unsigned short
      p_icmp.payload = d

            #print dir(p)
            #print type(p.payload)

    p_ip = ipv4()
    p_ip.protocol = p_ip.ICMP_PROTOCOL
    p_ip.srcip = dstip  # srcip, dstip in the argument is from the ping
    p_ip.dstip = srcip
    r = str(dstip).split('.')
    q = str(srcip).split('.')

    e = ethernet()
    e.src = p.dst
    if r[2]==q[2] or icmp_type == pkt.TYPE_DEST_UNREACH:
      e.dst = p.src
    else:
      n_addr = IPAddr('10.0.%d.1' % int(q[2]) )
      e.dst = self.arpTable[dpid][n_addr].mac

    e.type = e.IP_TYPE

    p_ip.payload = p_icmp
    e.payload = p_ip

    msg = of.ofp_packet_out()
    msg.actions.append(of.ofp_action_output(port = of.OFPP_IN_PORT))
    msg.data = e.pack()
    msg.in_port = self.routing[dpid][srcip]
    event.connection.send(msg)




  def _handle_GoingUpEvent (self, event):
    self.listenTo(core.openflow)
    log.debug("Up...")

  def _handle_PacketIn (self, event):
    dpid = event.connection.dpid
    inport = event.port
    packet = event.parsed
    if not packet.parsed:
      log.warning("%i %i ignoring unparsed packet", dpid, inport)
      return
    """ FIREWALL"""

    p ="54312, 12311, 21311"
    blocking_port.update(int(x) for x in p.replace(",", " ").split())
    core.openflow.addListenerByName("PacketIn", firewall)


    if dpid not in self.arpTable:
      # New switch -- create an empty table
      self.arpTable[dpid] = {}
      for fake in self.fakeways:
        self.arpTable[dpid][IPAddr(fake)] = Entry(of.OFPP_NONE, dpid_to_mac(dpid))
    if dpid not in self.routing:
      # New switch -- create an empty table
      self.routing[dpid] = {}
      if dpid == 1:
        self.routing[dpid][IPAddr('10.0.2.1')]=1
        self.routing[dpid][IPAddr('10.0.3.1')]=2
      if dpid == 2:
        self.routing[dpid][IPAddr('10.0.1.1')]=1
        self.routing[dpid][IPAddr('10.0.3.1')]=2
      if dpid == 3:
        self.routing[dpid][IPAddr('10.0.1.1')]=1
        self.routing[dpid][IPAddr('10.0.2.1')]=2


    

    if packet.type == ethernet.LLDP_TYPE:
      # Ignore LLDP packets
      return

    if isinstance(packet.next, ipv4):

      dstaddr = packet.next.dstip
      srcaddr = packet.next.srcip
      n = str(dstaddr).split('.')
      l = str(srcaddr).split('.')
      log.debug("%i %i IP %s => %s here", dpid,inport,
                packet.next.srcip,packet.next.dstip)
      if n[2] != str(dpid) and l[2] != str(dpid) :
        log.debug("Not destined to this subnet: Packet Dropped")
        return
      # Send any waiting packets...
      self._send_lost_buffers(dpid, packet.next.srcip, packet.src, inport)

      # Learn or update port/MAC info
      if packet.next.srcip in self.arpTable[dpid]:
        if self.arpTable[dpid][packet.next.srcip] != (inport, packet.src):
          log.info("%i %i RE-learned %s", dpid,inport,packet.next.srcip)
      else:
        log.debug("%i %i learned %s ", dpid,inport,str(packet.next.srcip))
        self.arpTable[dpid][packet.next.srcip] = Entry(inport, packet.src)


      if packet.next.srcip not in self.routing[dpid]:
        self.routing[dpid][packet.next.srcip] = inport



      if n[0] != '10':
        self.icmp_message(dpid, packet, packet.next.srcip, packet.next.dstip, pkt.TYPE_DEST_UNREACH,event)
        return
      if n[1] != '0':
        self.icmp_message(dpid, packet, packet.next.srcip, packet.next.dstip, pkt.TYPE_DEST_UNREACH,event)
        return
      if n[2] != '1' and n[2] != '2' and n[2] != '3':
        self.icmp_message(dpid, packet, packet.next.srcip, packet.next.dstip, pkt.TYPE_DEST_UNREACH,event)
        return
      if n[2] == '1':
        if n[3] != '2' and n[3] != '3' and n[3] != '1' and n[3] != '4':
          self.icmp_message(dpid, packet, packet.next.srcip, packet.next.dstip, pkt.TYPE_DEST_UNREACH,event)
          return
      if n[2] == '2':
        if n[3] != '2' and n[3] != '1' and n[3] != '3' and n[3] != '4':
          self.icmp_message(dpid, packet, packet.next.srcip, packet.next.dstip, pkt.TYPE_DEST_UNREACH,event)
          return
      if n[2] == '3':
        if n[3] != '2' and n[3] != '1' and n[3] != '3' and n[3] != '4':
          self.icmp_message(dpid, packet, packet.next.srcip, packet.next.dstip, pkt.TYPE_DEST_UNREACH,event)
          return
     # Try to forward
      if dstaddr in self.fakeways and int(n[2])==dpid:
        if isinstance(packet.next.next,icmp):
          if packet.next.next.type == pkt.TYPE_ECHO_REQUEST:
            self.icmp_message(dpid, packet, packet.next.srcip, packet.next.dstip, pkt.TYPE_ECHO_REPLY, event)
      elif n[2]==l[2]:
        if dstaddr not in self.routing[dpid] or dstaddr not in self.arpTable[dpid]:
          if (dpid,dstaddr) not in self.lost_buffers:
            self.lost_buffers[(dpid,dstaddr)] = []
          bucket = self.lost_buffers[(dpid,dstaddr)]
          entry = (time.time() + MAX_BUFFER_TIME,event.ofp.buffer_id,inport)
          bucket.append(entry)
          while len(bucket) > MAX_BUFFERED_PER_IP: del bucket[0]


        # Expire things from our outstanding ARP list...
          self.outstanding_arps = {k:v for k,v in
              self.outstanding_arps.iteritems() if v > time.time()}

        # Check if we've already ARPed recently
          if (dpid,dstaddr) in self.outstanding_arps:
          # Oop, we've already done this one recently.
            return
          r = arp()
          r.hwtype = r.HW_TYPE_ETHERNET
          r.prototype = r.PROTO_TYPE_IP
          r.hwlen = 6
          r.protolen = r.protolen
          r.opcode = r.REQUEST
          r.hwdst = ETHER_BROADCAST
          r.protodst = dstaddr
          r.hwsrc = packet.src
          r.protosrc = packet.next.srcip
          e = ethernet(type=ethernet.ARP_TYPE, src=packet.src,
                     dst=ETHER_BROADCAST)
          e.set_payload(r)
          log.debug("%i %i ARPing for %s on behalf of %s" % (dpid, inport,
          str(r.protodst), str(r.protosrc)))
          msg = of.ofp_packet_out()
          msg.data = e.pack()
          msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
          msg.in_port = inport
          event.connection.send(msg)
        if dstaddr in self.arpTable[dpid]:
        # We have info about what port to send it out on...

          prt = self.arpTable[dpid][dstaddr].port
          mac = self.arpTable[dpid][dstaddr].mac
          log.debug("%i %i installing flow for %s => %s out port %i"
                    % (dpid, inport, packet.next.srcip, dstaddr, prt))

          actions = []
          actions.append(of.ofp_action_dl_addr.set_dst(mac))
          actions.append(of.ofp_action_output(port = prt))
          match = of.ofp_match.from_packet(packet, inport)
          match.dl_src = None # Wildcard source MAC

          msg = of.ofp_flow_mod(command=of.OFPFC_ADD,
                                idle_timeout=FLOW_IDLE_TIMEOUT,
                                hard_timeout=of.OFP_FLOW_PERMANENT,
                                buffer_id=event.ofp.buffer_id,
                                actions=actions,
                                match=of.ofp_match.from_packet(packet,
                                                               inport))
          event.connection.send(msg.pack())
      else:
        if dstaddr in self.arpTable[dpid]:
                n_addr = IPAddr('10.0.%d.1' % int( n[2]))
                mac = self.arpTable[dpid][dstaddr].mac
                prt = self.routing[dpid][dstaddr]

                actions = []
                actions.append(of.ofp_action_dl_addr.set_dst(mac))
                actions.append(of.ofp_action_output(port = prt))
                match = of.ofp_match.from_packet(packet, inport)
                match.dl_src = None # Wildcard source MAC

                msg = of.ofp_flow_mod(command=of.OFPFC_ADD,
                                      idle_timeout=FLOW_IDLE_TIMEOUT,
                                      hard_timeout=of.OFP_FLOW_PERMANENT,
                                      buffer_id=event.ofp.buffer_id,
                                      actions=actions,
                                      match=of.ofp_match.from_packet(packet,
                                                                       inport))
                event.connection.send(msg.pack())


        elif self.arp_for_unknowns:
                if dstaddr not in self.routing[dpid] or dstaddr not in self.arpTable[dpid]:
                  if (dpid,dstaddr) not in self.lost_buffers:
                    self.lost_buffers[(dpid,dstaddr)] = []
                  bucket = self.lost_buffers[(dpid,dstaddr)]
                  entry = (time.time() + MAX_BUFFER_TIME,event.ofp.buffer_id,inport)
                  bucket.append(entry)
                  while len(bucket) > MAX_BUFFERED_PER_IP: del bucket[0]


                # Expire things from our outstanding ARP list...
                  self.outstanding_arps = {k:v for k,v in
                      self.outstanding_arps.iteritems() if v > time.time()}

                # Check if we've already ARPed recently
                  if (dpid,dstaddr) in self.outstanding_arps:
                  # Oop, we've already done this one recently.
                    return
                  r = arp()
                  r.hwtype = r.HW_TYPE_ETHERNET
                  r.prototype = r.PROTO_TYPE_IP
                  r.hwlen = 6
                  r.protolen = r.protolen
                  r.opcode = r.REQUEST
                  r.hwdst = ETHER_BROADCAST
                  r.protodst = dstaddr
                  r.hwsrc = packet.src
                  r.protosrc = packet.next.srcip
                  e = ethernet(type=ethernet.ARP_TYPE, src=packet.src,
                             dst=ETHER_BROADCAST)
                  e.set_payload(r)
                  log.debug("%i %i ARPing for %s on behalf of %s" % (dpid, inport,
                  str(r.protodst), str(r.protosrc)))
                  msg = of.ofp_packet_out()
                  msg.data = e.pack()
                  msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
                  msg.in_port = inport
                  event.connection.send(msg)
    elif isinstance(packet.next, arp):
      a = packet.next
      n = str(packet.next.protodst).split('.')
      l = str(packet.next.protosrc).split('.')
      log.debug("%i %i ARP %s %s => %s", dpid, inport, {arp.REQUEST:"request",arp.REPLY:"reply"}.get(a.opcode, 'op:%i' % (a.opcode,)), str(a.protosrc), str(a.protodst))
      if n[2] != str(dpid) and l[2] != str(dpid):
        log.debug("Not destined to this subnet: Packet Dropped")
        return
      flag = 0
      q = str(a.protodst).split('.')


      if a.prototype == arp.PROTO_TYPE_IP:
        if a.hwtype == arp.HW_TYPE_ETHERNET:
          if a.protosrc != 0:

            # Learn or update port/MAC info
            if a.protosrc in self.arpTable[dpid]:
              if self.arpTable[dpid][a.protosrc] != (inport, packet.src):
                log.info("%i %i RE-learned %s", dpid,inport,str(a.protosrc))
            else:
              log.debug("%i %i learned %s", dpid,inport,str(a.protosrc))
            self.arpTable[dpid][a.protosrc] = Entry(inport, packet.src)

            if packet.next.protosrc not in self.routing[dpid]:
              self.routing[dpid][packet.next.protosrc] = inport

            # Send any waiting packets..
            self._send_lost_buffers(dpid, a.protosrc, packet.src, inport)

            if a.opcode == arp.REQUEST:
              # Maybe we can answer

              if a.protodst in self.arpTable[dpid]:
                # We have an answer...

                if self.arpTable[dpid][a.protodst] or (self.fakeways and int(n[2]) == dpid):
                  # .. and it's relatively current, so we'll reply ourselves

                  r = arp()
                  r.hwtype = a.hwtype
                  r.prototype = a.prototype
                  r.hwlen = a.hwlen
                  r.protolen = a.protolen
                  r.opcode = arp.REPLY
                  r.hwdst = a.hwsrc
                  r.protodst = a.protosrc
                  r.protosrc = a.protodst
                  r.hwsrc = self.arpTable[dpid][a.protodst].mac
                  e = ethernet(type=packet.type, src=dpid_to_mac(dpid),
                               dst=a.hwsrc)
                  e.set_payload(r)
                  log.debug("%i %i answering ARP for %s" % (dpid, inport,
                   str(r.protosrc)))
                  msg = of.ofp_packet_out()
                  msg.data = e.pack()
                  msg.actions.append(of.ofp_action_output(port =
                                                          of.OFPP_IN_PORT))
                 
                  msg.in_port = inport
                  event.connection.send(msg)
                  return
                else:
                  n_addr = IPAddr('10.0.%d.1' % int(n[2]))
                  mac = self.arpTable[dpid][n_addr].mac
                  prt = self.routing[dpid][a.protodst]
                  r = arp()
                  r.hwtype = a.hwtype
                  r.prototype = a.prototype
                  r.hwlen = a.hwlen
                  r.protolen = a.protolen
                  r.opcode = arp.REPLY
                  r.hwdst = mac
                  r.protodst = a.protosrc
                  r.protosrc = a.protodst
                  r.hwsrc = self.arpTable[dpid][a.protodst].mac
                  e = ethernet(type=packet.type, src=dpid_to_mac(dpid),
                               dst=a.hwdst)
                  e.set_payload(r)
                  log.debug("%i %i answering ARP for %s" % (dpid, inport,
                   str(r.protosrc)))
                  msg = of.ofp_packet_out()
                  msg.data = e.pack()
                  msg.actions.append(of.ofp_action_output(port =
                                                          prt))
           
                  msg.in_port = inport
                  event.connection.send(msg)
                  return
            elif a.opcode == arp.REPLY and a.protodst != IPAddr('10.0.%d.1' % (dpid)):
              if a.protodst in self.routing[dpid] and n[2] != l[2] and inport != 1 and inport!=2:
                flag = 1
                n_addr = IPAddr('10.0.%d.1' % int(n[2]))
                prt = self.routing[dpid][a.protodst]

                msg = of.ofp_packet_out()
                msg.data = event.ofp
                action = of.ofp_action_output(port = prt)
                msg.actions.append(action)
                event.connection.send(msg)
              else:
                flag = 1
                msg = of.ofp_packet_out(in_port = inport, data = event.ofp,
                        action = of.ofp_action_output(port = of.OFPP_FLOOD))
                event.connection.send(msg)

      if flag == 0:
      # Didn't know how to answer or otherwise handle this ARP, so just flood it
        log.debug("%i %i flooding ARP %s %s => %s" % (dpid, inport,
         {arp.REQUEST:"request",arp.REPLY:"reply"}.get(a.opcode,
         'op:%i' % (a.opcode,)), str(a.protosrc), str(a.protodst)))

        msg = of.ofp_packet_out(in_port = inport, data = event.ofp,
          action = of.ofp_action_output(port = of.OFPP_FLOOD))
        event.connection.send(msg)


def launch (fakeways="10.0.1.1, 10.0.2.1, 10.0.3.1", arp_for_unknowns=None):
  fakeways = fakeways.replace(","," ").split()
  fakeways = [IPAddr(x) for x in fakeways]
  if arp_for_unknowns is None:
    arp_for_unknowns = len(fakeways) > 0
  else:
    arp_for_unknowns = str_to_bool(arp_for_unknowns)
  core.registerNew(l3_switch, fakeways, arp_for_unknowns)
