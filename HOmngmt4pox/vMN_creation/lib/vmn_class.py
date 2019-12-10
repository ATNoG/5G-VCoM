"""
vMobile Node Class
"""

class vMobileNode():
  def __init__(self):
    self.vmnid = None # Mobile Node identifier
    self.mnid = None # Mobile Node identifier
    self.brid = None # bridge ID
    self.vmnip = None # MN has a unique IP
    self.mnip1 = None # MAC AP1 - attach to wlan0
    self.mnip2 = None # MAC AP2 - attach to wlan1
    self.ap1 = None
    self.ap2 = None