#!/bin/python
from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.addresses import IPAddr, EthAddr
from pox.lib.util import dpid_to_str
from pox.lib.revent import *
from var import *
from vmn_class import *
all_vmn = []
counter_mnid = 0

def isMobileNode(src_ip, dst_ip, protocol, tp_dst):
  """
  Verify if the packet_in is regarded to a MN attachment.
  """
  if ((dst_ip == ip_mn2vmn) and (protocol == proto_OF) and (tp_dst==of_port)):
    return True
  return False

def add_vMN(vmn_dpid, vmn_ip, mn_ip1, mn_ip2):
  """
  add or update the vMN list
  """
  global all_vmn
  global counter_mnid
  updated = False

  if (mn_ip1 != None): mn_id = get_MNid(mn_ip1)
  elif (mn_ip2 != None): mn_id = get_MNid(mn_ip2)

  if all_vmn:
    if (vmn_dpid in all_vmn):
      for vmn in all_vmn:
        if ((vmn.brid == vmn_brid) and (vmn.vmnip == vmn_ip)):
          updated = True
          if (mn_ip1 != None): vmn.mnip1=mn_ip1
          if (mn_ip2 != None): vmn.mnip2=mn_ip2
          if (mn_id != -1): vmn.mnid=mn_id
  
  if updated:
    return
  else:        
    vmn=vMobileNode()
    vmn.brid = vmn_dpid
    vmn.vmnip = vmn_ip
    if (mn_ip1 != None): vmn.mnip1=mn_ip1
    if (mn_ip2 != None): vmn.mnip2=mn_ip2
    if (mn_id != -1): vmn.mnid=mn_id
    all_vmn.append(vmn)
    return

def is_vMNrequest(dst_ip, protocol, tp_dst):
  """
  Verify if the packet_in is regarded to a new vMN creation.
  """
  if ((dst_ip in all_mn_id.iterkeys()) and (protocol == proto_UDP) and (tp_dst==vmn_port)):
    return True
  return False

def is_vAP1(ports):
  """
  Verify vAP1 connection
  """
  for m in ports:
    if (m.name == vap1_br): return True
  return False

def is_vAP2(ports):
  """
  Verify vAP2 connection
  """
  for m in ports:
    if (m.name == vap2_br): return True
  return False

def is_vMN(ports):
  """
  Verify vAP2 connection
  """
  for m in ports:
    if (m.name == vmn_br): return True
  return False

def isHandover(dst_ip, protocol, tp_dst):
  """
  Verify handover request
  """
  if ((dst_ip in all_mn_id.iterkeys()) and (protocol == proto_UDP) and (tp_dst==ho_port)):
    return True
  return False

def get_MNid(mn_ip):
  """
  Returns mobile node ID
  otherwise, returns -1
  """
  for mnip in all_mn_id.iterkeys():
    if (mnip == mn_ip):
      return all_mn_id[mnip]
  return -1


def get_vMN(mn_id):
  """
  Verify if the MN has a virtual representation already, 
  or if it is needed a new one.
  If exists: return the IP
  else: return -1 
  """
  if (mn_id in all_vmn):
    return mn_id.vmnip
  return -1

def create_vMN(ipMN):
  import os
  os.system("bash ~/nova.sh -ip "+str(ipMN))
  return

def updateAP_flowtable(brid, old_src_ip, old_dst_ip, new_src_ip, new_dst_ip, output_port):
  """
  All received MN traffic in vAP will be sent to its vMN
  """
  
  msg = of.ofp_flow_mod()
  msg.priority = 100
  
  msg.match.dl_type = 0x800
  msg.match.nw_dst = old_dst_ip
  msg.match.nw_src = old_src_ip

  msg.actions.append(of.ofp_action_dl_addr.set_src(EthAddr((router_eth_ap))))
  msg.actions.append(of.ofp_action_dl_addr.set_dst(EthAddr((mn1_mac2))))
  msg.actions.append(of.ofp_action_nw_addr.set_src(new_src_ip))
  msg.actions.append(of.ofp_action_nw_addr.set_dst(new_dst_ip))
  msg.actions.append(of.ofp_action_output(port = output_port))
  core.openflow.sendToDPID(brid,msg)
  return 

def updatevMN_flowtable(brid, old_src_ip, old_dst_ip, new_src_ip, new_dst_ip, protocol, protocol_port, output_port):
  """
  if traffic is OpenFlow: 
    modify to the correct src_ip and send to the vMN's kernel
  else
    send to the correct receiver and update src_ip
  """
    
  msg = of.ofp_flow_mod()
  msg.priority = 100
  
  msg.match.dl_type = 0x800
  msg.match.nw_dst = old_dst_ip
  msg.match.nw_src = old_src_ip
  
  if (protocol != None):
    msg.match.nw_proto = protocol
  if (protocol_port != None):
    msg.match.tp_dst = protocol_port
    if (protocol_port == of_port):
      outport = 0

  msg.actions.append(of.ofp_action_dl_addr.set_src(EthAddr((vmn_eth))))
  msg.actions.append(of.ofp_action_dl_addr.set_dst(EthAddr((router_eth_vmn))))
  msg.actions.append(of.ofp_action_nw_addr.set_src(new_src_ip))
  msg.actions.append(of.ofp_action_nw_addr.set_dst(new_dst_ip))
  msg.actions.append(of.ofp_action_output(port = output_port))
  core.openflow.sendToDPID(brid,msg)
  return

def is_vAPrequest(dstip, protocol, dstport):
  """
  verify if packet_in is related a HO request from vAP
  """
  if ((dstip == ip_pkt_in) and (protocol == proto_UDP) and (dstport==ho_port)):
    return True
  return False

def is_download(dstip, protocol, dstport):
  """
  verify if packet_in is related a HO request from vAP
  """
  if ((dstip == ip_pkt_in2) and (protocol == proto_UDP) and (dstport==ho_port)):
    return True
  return False


def advert_vMN(vmn_dpid, buffer_id, raw_data):
  """
  Asks the vMN to handle the MN HO
  """
  msg = of.ofp_packet_out(in_port=of.OFPP_NONE)
  msg.actions.append(of.ofp_action_output(port = of.OFPP_CONTROLLER))
  msg.buffer_id = buffer_id
  msg.data = raw_data
  core.openflow.sendToDPID(vmn_dpid,msg)

def is_vMNout(srcip,dstip):
  if((srcip == vap1_ip) and (dstip == ip_pkt_in)):
    return True
  return False