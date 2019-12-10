"""
Envent Handler
"""
from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.util import dpid_to_str
from pox.lib.revent import *
#from datetime import datetime
from lib import *
from lib.func import *

log = core.getLogger()
MN = 0;
class ConnectionUp(Event):
  def __init__(self,connection,ofp):
    Event.__init__(self)
    self.connection = connection
    self.dpid = connection.dpid
    self.ofp = ofp

class ConnectionDown(Event):
  def __init__(self,connection,ofp):
    Event.__init__(self)
    self.connection = connection
    self.dpid = connection.dpid

class PacketIn(Event):
  def __init__(self,connection,ofp):
    Event.__init__(self)
    self.connection = connection
    self.dpid = connection.dpid 

class MyEvents(object):
  def __init__(self):
    core.openflow.addListeners(self)

  def _handle_ConnectionUp(self,event):
    """
    Only accepts MNs requests
    """
    if isMobileNode(event.connection.features.ports):
      ConnectionUp(event.connection,event.ofp)
      addMobileNode(event.connection)
      #global MN += 1
      
      # Handover request rule
      event.connection.send( of.ofp_flow_mod( 
        action=of.ofp_action_output( port=of.OFPP_CONTROLLER ), priority=99,
        match=of.ofp_match( dl_type=0x800, nw_dst=ip_pkt_in, nw_proto=proto_UDP, tp_dst=ho_port_mn )))

      event.connection.send( of.ofp_flow_mod( 
        action=of.ofp_action_output( port=of.OFPP_CONTROLLER ), priority=99,
        match=of.ofp_match( dl_type=0x800, nw_dst=ip_pkt_in, nw_proto=proto_UDP, tp_dst=ho_port_ctl )))
      
      #if MN == 1:
        # inform CTL
      log.info("Switch %s UP.",dpid_to_str(event.dpid))

  def _handle_ConnectionDown(self,event):
    """
    Only accepts MNs requests
    """
    if isMobileNode(event.connection.features.ports):
      ConnectionDown(event.connection,event.dpid)
      
      delMobileNode(event.connection)
      #global MN -= 1
      #if MN == 0:
        # inform CTL
      log.info("Switch %s DOWN.",dpid_to_str(event.dpid))

  def _handle_PacketIn(self,event):
    """
    Verify if packet is regarded to a handover request
    """
    PacketIn(event.connection,event.ofp)
    packet = event.parsed
  
    if packet.type == of.ethernet.IP_TYPE:
      ipv4_packet = event.parsed.find("ipv4")
      match = of.ofp_match.from_packet(packet)

      log.info(">>> Packet_in <<<")
      log.debug("[ br_dpid: %s || src_ip: %s || dst_ip: %s ]",
                dpid_to_str(event.dpid),ipv4_packet.srcip,ipv4_packet.dstip)
  
      if ((ipv4_packet.dstip == ip_pkt_in) and (ipv4_packet.protocol == proto_UDP)):
        log.info(">>> handover request (MN) <<<")
        handoverRequest(event.dpid)

  def _handle_BarrierIn(self,event):
    """
    Verify if packet is regarded to a handover request
    """
    checkBarrier(event.ofp.xid, event.connection.dpid)

def launch():
  core.registerNew(MyEvents)