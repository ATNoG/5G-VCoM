"""
Auxiliar functions
"""
from pox.core import core
from pox.lib.util import dpid_to_str
from pox.lib.util import str_to_dpid
import pox.openflow.libopenflow_01 as of
from mn_class import *
from var import *

log = core.getLogger()
mn = mobileNode()
mnCounter = 0
mn.vmnid = str_to_dpid("ca-5a-d3-75-d8-49")

def isMobileNode(ports):
  """
  Verify if it is a MN through wireless port name
  """
  for m in ports:
    if ((m.name == interfaceName0) or (m.name == interfaceName1)):
      return True

  return False

def addMobileNode(connection):
  """
  Adds and Updates the MN information
  """
  global mn
  global mnCounter
   
  for m in connection.features.ports:
    if (m.name == interfaceName0):
      mn.brid0 = connection.dpid
      mn.mac0 = m.hw_addr
      mn.num_wlan0 = m.port_no
      mn.nports += 1 
      continue

    if (m.name == interfaceName1):
      mn.brid1 = connection.dpid
      mn.mac1 = m.hw_addr
      mn.num_wlan1 = m.port_no
      mn.nports += 1
      continue

    if (m.name == patchName0):
      mn.num_patch0 = m.port_no
      continue

    if (m.name == patchName1):
      mn.num_patch1 = m.port_no
      continue

    if (m.name == vmnbr_name):
      mn.vmnid = connection.dpid
      continue

  mnCounter += 1
  mn.number = mnCounter
  printMNinformation()

def delMobileNode(connection):
  """
  Removes and Updates the MN information
  """
  global mn
  global mnCounter 

  if (mn.brid0 == connection.dpid):
    mn.brid0 = None
    mn.mac0 = None
    mn.num_wlan0 = None
    mn.nports -= 1

    if (mn.brid1 == None):
      log.info("[ MobileNode n%s was completly >> DOWN << ]",mn.number)
      mnCounter -= 1
      return

    log.info("[ MobileNode n%s was interface BR %s >> DOWN << ]",mn.number,dpid_to_str(connection.dpid))
    return
  
  if (mn.brid1 == connection.dpid):
    mn.brid1 = None
    mn.mac1 = None
    mn.num_wlan1 = None
    mn.nports -= 1
    
    if (mn.brid0 == None):
      log.info("[ MobileNode n%s was completly >> DOWN << ]",mn.number)
      mnCounter -= 1
      return
    
    log.info("[ MobileNode n%s was interface BR %s >> DOWN << ]",mn.number,dpid_to_str(connection.dpid))
    return

def handoverRequest(MNdpid):
  """
  Sends the first handover rule followed by a barrier request
  this first rules is a pre-configuration for the new wireless interfac
  """
  global mn
  
  if ((mn.nports < 2) or ((mn.brid0 == None) and (mn.brid1 == None))):
    log.debug(">>> Handover not performed! Multihoming not found! <<<")
    return
  
  if (MNdpid == mn.brid0):
    send_flow2mn(mn.brid0, mn.mac0, vap1_mac, mn.num_patch0, mn.num_wlan0)
    send_barrier(mn.brid0)
    return
  if (MNdpid == mn.brid1):
    send_flow2mn(mn.brid1, mn.mac1, vap2_mac, mn.num_patch1, mn.num_wlan1)
    send_barrier(mn.brid1)
    return

  if (MNdpid == mn.vmnid):
    send_flow2mn(mn.brid1, mn.mac1, vap2_mac, mn.num_patch1, mn.num_wlan1)
    send_barrier(mn.brid1)
    return

def send_flow2mn (brid, mac_src, mac_dst, in_port, output_port):
  """
  Sends handover rule to the mobile node
  """
  global mn
  
  msg = of.ofp_flow_mod()
  msg.priority = 100
  
  if (in_port != None): 
    msg.match.in_port = in_port
  
  msg.match.dl_type = 0x800
  msg.match.nw_dst = handoverData[0]
  msg.match.nw_proto = handoverData[1]
  msg.match.tp_dst = int(handoverData[2])

  if (mac_src != None): 
    msg.actions.append(of.ofp_action_dl_addr.set_src(dl_addr=mac_src))
  if (mac_dst != None): 
    msg.actions.append(of.ofp_action_dl_addr.set_dst(dl_addr=mac_dst))
  msg.actions.append(of.ofp_action_output(port = output_port))

  # send message to MN
  core.openflow.sendToDPID(brid,msg)
  
def send_barrier(brid):
  """
  Sends a barrier request to ensure the 
  flow_mod implementation
  """
  global mn
  b = of.ofp_barrier_request()
  mn.bxid = b.xid
  core.openflow.sendToDPID(brid,b)

def checkBarrier(bxid, brid):
  """
  Checks if the barrier is from the MN
  if true - sends the second handover rule
  """
  global mn
  if (mn.bxid == None): return

  if (bxid == mn.bxid):
    if (brid == mn.brid0): 
      send_flow2mn(mn.brid1, None, None, None, mn.num_patch0)
      return
    if (brid == mn.brid1): 
      send_flow2mn(mn.brid0, None, None, None, mn.num_patch1)
      return

def printMNinformation():
  """
  Prints MN information
  """
  global mn

  log.debug(">>> Mobile DataBase UPDATE <<<")
  if mn.brid0 != None:
    log.debug("[ BR0 DPID = %s", dpid_to_str(mn.brid0))
    log.debug("  MAC0 = %s", mn.mac0)
    log.debug("  Wlan0 n_port = %s", mn.num_wlan0)
    log.debug("  PatchPort0 n_port = %s ]", mn.num_patch0)
  
  if mn.brid1 != None:
    log.debug("[ BR1 DPID = %s", dpid_to_str(mn.brid1))
    log.debug("  MAC1 = %s", mn.mac1)
    log.debug("  Wlan1 n_port = %s", mn.num_wlan1)
    log.debug("  PatchPort1 n_port = %s ]", mn.num_patch1)