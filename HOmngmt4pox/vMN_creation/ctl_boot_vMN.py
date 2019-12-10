"""
Envent Handler
"""
from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.util import dpid_to_str
from pox.lib.revent import *
#from datetime import datetime
from lib import *
from lib.ctl_boot_vMN_func import *

waitingList = []
vap1_dpid = None
vap2_dpid = None
vmn_dpid = None
#vap1_ip = None
#vap2_ip = None
log = core.getLogger()

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
    on connection up the controller installs a packet in rule on bridges
    """
    global vap1_dpid
    global vap2_dpid
    global vmn_dpid

    ConnectionUp(event.connection,event.ofp)
    
    event.connection.send( of.ofp_flow_mod( action=of.ofp_action_output( port=10 ), priority=0))

    if is_vAP1(event.connection.features.ports): 
      vap1_dpid = event.connection.dpid
      # packet_in rule to get vMN ip
      event.connection.send( of.ofp_flow_mod( action=of.ofp_action_output( port=of.OFPP_CONTROLLER ), priority=1,
                                             match=of.ofp_match( dl_type=0x800, nw_dst=ip_mn2vmn, 
                                                                nw_proto = proto_OF, tp_dst = of_port )))
      event.connection.send( of.ofp_flow_mod( action=of.ofp_action_output( port=of.OFPP_CONTROLLER ), priority=2,
                                             match=of.ofp_match( dl_type=0x800, nw_dst=ip_pkt_in, 
                                                                nw_proto = proto_UDP, tp_dst = ho_port )))
      event.connection.send( of.ofp_flow_mod( action=of.ofp_action_output( port=of.OFPP_CONTROLLER ), priority=2,
                                             match=of.ofp_match( dl_type=0x800, nw_dst=ip_pkt_in2, 
                                                                nw_proto = proto_UDP, tp_dst = ho_port )))
    elif is_vAP2(event.connection.features.ports): 
      vap2_dpid = event.connection.dpid
      # packet_in rule to get vMN ip
      event.connection.send( of.ofp_flow_mod( action=of.ofp_action_output( port=of.OFPP_CONTROLLER ), priority=1,
                                             match=of.ofp_match( dl_type=0x800, nw_dst=ip_mn2vmn, 
                                                                nw_proto = proto_OF, tp_dst = of_port )))      
      event.connection.send( of.ofp_flow_mod( action=of.ofp_action_output( port=of.OFPP_CONTROLLER ), priority=2,
                                             match=of.ofp_match( dl_type=0x800, nw_dst=ip_pkt_in, 
                                                                nw_proto = proto_UDP, tp_dst = ho_port )))
      event.connection.send( of.ofp_flow_mod( action=of.ofp_action_output( port=of.OFPP_CONTROLLER ), priority=2,
                                             match=of.ofp_match( dl_type=0x800, nw_dst=ip_pkt_in2, 
                                                                nw_proto = proto_UDP, tp_dst = ho_port )))
    elif is_vMN(event.connection.features.ports):
      vmn_dpid = event.connection.dpid
      event.connection.send( of.ofp_flow_mod( action=of.ofp_action_output( port=of.OFPP_CONTROLLER ), priority=2,
                                             match=of.ofp_match( dl_type=0x800, nw_dst=ip_pkt_in, 
                                                                nw_proto = proto_UDP, tp_dst = ho_port )))
      """
      event.connection.send( of.ofp_flow_mod( action=of.ofp_action_output( port=outport_vmn_eth0 ), priority=1,
                                             match=of.ofp_match( dl_type=0x800, nw_dst=cn_ip, 
                                                                nw_proto = handoverData[1], tp_dst = handoverData[2] )))
      """

  def _handle_ConnectionDown(self,event):
    ConnectionDown(event.connection,event.dpid)
    #if is_vMN(event):
      # remove from list

    log.info("Switch %s DOWN.",dpid_to_str(event.dpid))

  def _handle_PacketIn(self,event):
    global waitingList
    #global vmn_dpid
    #global vap1_ip
    #global vap2_ip

    PacketIn(event.connection,event.ofp)
    packet = event.parsed
    packet_in = event.ofp
    #pckin_ip_src = packet.srcip
    dst_port = 6633
    tcpp = event.parsed.find('tcp')
    if tcpp: dst_port = tcpp.dstport 
    udpp = event.parsed.find('udp')
    if udpp: dst_port = udpp.dstport 
    if packet.type == of.ethernet.IP_TYPE:
      ipv4_packet = event.parsed.find("ipv4")

      log.info(">>> Packet_in <<<")
      log.debug("[MN = %s || AP = %s]", ipv4_packet.srcip, dpid_to_str(event.dpid))
      log.debug("[ br_dpid: %s || src_ip: %s || dst_ip: %s ]",dpid_to_str(event.dpid),ipv4_packet.srcip,ipv4_packet.dstip)
      if (vmn_dpid != None):
        if ((event.connection.dpid == vmn_dpid) and is_vMNout(ipv4_packet.srcip,ipv4_packet.dstip)):
          return
      if isMobileNode(ipv4_packet.srcip, ipv4_packet.dstip, ipv4_packet.protocol, dst_port):
        if (ipv4_packet.srcip not in waitingList):
          mn_id = get_MNid(ipv4_packet.srcip)
          vmn_ip = get_vMN(mn_id)
          if (vmn_ip == -1):
            waitingList.append(ipv4_packet.srcip)
            create_vMN(ipv4_packet.srcip)
          else:
            #update MNid
            add_vMN(event.connection.dpid, ipv4_packet.srcip, None, ipv4_packet.dstip)
            # AP -> vMN (brid, old_src_ip, old_dst_ip, new_src_ip, new_dst_ip, output_port)
            updateAP_flowtable(vap2_dpid, ipv4_packet.srcip, None, vap2_ip, vmn_ip, outport_ap_eth0)
            # AP -> MN (brid, old_src_ip, old_dst_ip, new_src_ip, new_dst_ip, output_port)
            updateAP_flowtable(vap2_dpid, vmn_ip, vap2_ip, vap2_ip, ipv4_packet.srcip, outport_ap_wlan0)
      elif udpp:
        if is_vMNrequest(ipv4_packet.dstip, ipv4_packet.protocol, dst_port):
          vmn_ip = ipv4_packet.srcip
          # update MN ID
          add_vMN(vmn_dpid, ipv4_packet.srcip, ipv4_packet.dstip, None)
          # AP -> vMN (brid, old_src_ip, old_dst_ip, new_src_ip, new_dst_ip, output_port)
          updateAP_flowtable(vap1_dpid, ipv4_packet.dstip, None, vap1_ip, ipv4_packet.srcip, outport_ap_eth0)
          # AP -> MN (brid, old_src_ip, old_dst_ip, new_src_ip, new_dst_ip, output_port)
          updateAP_flowtable(vap1_dpid, ipv4_packet.srcip, vap1_ip, vap1_ip, ipv4_packet.dstip, outport_ap_wlan0)
          if (ipv4_packet.dstip in waitingList): waitingList.remove(ipv4_packet.dstip)

        elif isHandover(ipv4_packet.dstip, ipv4_packet.protocol, dst_port):
          vmn_ip = ipv4_packet.srcip
          #vmn_dpid = event.connection.dpid
          # vMN -> AP2 (brid, old_src_ip, old_dst_ip, new_src_ip, new_dst_ip, protocol, protocol_port, output_port)
          updatevMN_flowtable(vmn_dpid, cn_ip, vmn_ip, vmn_ip, vap2_ip, handoverData[1], handoverData[2],outport_vmn_eth0)
          # vMN -> CN (brid, old_src_ip, old_dst_ip, new_src_ip, new_dst_ip, protocol, protocol_port, output_port)
          updatevMN_flowtable(vmn_dpid, vap2_ip, vmn_ip, vmn_ip, cn_ip, handoverData[1], handoverData[2],outport_vmn_eth0)

        elif is_vAPrequest(ipv4_packet.dstip, ipv4_packet.protocol, dst_port):
          advert_vMN(vmn_dpid, packet_in.buffer_id, packet_in.data)

        elif is_download(ipv4_packet.dstip, ipv4_packet.protocol, dst_port):
          updatevMN_flowtable(vmn_dpid, cn_ip, vmn_ip, vmn_ip, vap2_ip, handoverData[1], handoverData[2],outport_vmn_eth0)
          updateAP_flowtable(vap2_dpid, vmn_ip, vap2_ip, vap2_ip, ipv4_packet.srcip, outport_ap_wlan0)
         
def launch():
  core.registerNew(MyEvents)