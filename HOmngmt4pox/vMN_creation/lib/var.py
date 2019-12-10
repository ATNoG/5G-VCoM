"""
Initialize some variables
"""
import pox.openflow.libopenflow_01 as of
import pox.lib.packet as pkt

# Mobile node eth interfaces
mn1_mac1="04:f0:21:17:36:46"
mn1_ip1="192.168.10.1"

mn1_mac2="04:f0:21:14:c5:66"
mn1_ip2="192.168.11.1"

vMN_mac=""
vMN_ip=""

all_mn_id = {mn1_ip1:'id1', mn1_ip2:'id1'}
#all_mn_id = {mn1_ip1:'id1', mn1_ip2:'id1', mn2_ip1:'id2', mn2_ip2:'id2' }

cn_ip="10.110.1.24"
vap1_br="vap1"
vap2_br="vap2"
vmn_br="br0"

# AP eth interfaces
vap1_mac="fa:16:3e:6b:6f:51"
vap2_mac="fa:16:3e:58:f8:05"
vap1_ip="10.5.52.60"
vap2_ip="10.5.52.41"

# handover
linkup_port = 58550
linkdown_port = 58551
linkgoingdown_port = 58552
of_port = 6633
vmn_port = 58549
ho_port = 58550
proto_UDP = pkt.ipv4.UDP_PROTOCOL
proto_TCP = pkt.ipv4.TCP_PROTOCOL
proto_OF = pkt.ipv4.TCP_PROTOCOL
handoverData = ["192.168.10.1" , proto_UDP, 5004]
ip_pkt_in = "11.11.11.11"
ip_pkt_in2 = "22.22.22.22"
ip_mn2vmn = "192.168.10.253"

outport_ap_eth0 = 1
outport_ap_wlan0 = 2
outport_vmn_eth0 = of.OFPP_IN_PORT

vmn_eth = "fa:16:3e:35:cc:2e"
router_eth_ap = "fa:16:3e:f9:c0:6f"
router_eth_vmn = "fa:16:3e:f6:90:af"