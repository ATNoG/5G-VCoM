"""
Mobile Node Class
"""

class mobileNode():
  def __init__(self):
    self.number = None

    self.bxid = None    # barrier ID, used in handover process
    self.brid0 = None   # bridge ID
    self.brid1 = None   # bridge ID
    self.vmnid = None
    
    self.mac0 = None    # MAC MN - wlan0
    self.mac1 = None    # MAC MN - wlan1
    
    self.num_wlan0 = None  # output port number br0
    self.num_wlan1 = None  # output port number br1
    self.num_patch0 = None
    self.num_patch1 = None

    self.ip0 = None     # IP MN - wlan0
    self.ip1 = None     # IP MN - wlan1
    
    self.ap1 = None    # MAC AP1 - attach to wlan0
    self.ap2 = None    # MAC AP2 - attach to wlan1
    
    self.nports = 0 # number of wireless interfaces attached
    # not in use
    #MNid = None # Mobile Node identifier