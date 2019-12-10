"""
Initialize some variables
"""
import pox.lib.packet as pkt

# MN interfaces
interfaceName0 = "wlan2"
interfaceName1 = "wlan3"
patchName0 = "patch01"
patchName1 = "patch10"
vmnbr_name = "br0"

# AP eth interfaces
vap1_mac="02:00:00:00:00:00"
vap2_mac="00:11:22:33:44:55"
vap1_ip="10.5.52.60"
vap2_ip="10.5.52.41"

# handover
ip_pkt_in = "11.11.11.11"
ip_flow_handover = "192.168.10.3"
of_port = 6633
ho_port_mn = 58549
ho_port_ctl = 58550
port_flow_handover = 5004
proto_UDP = pkt.ipv4.UDP_PROTOCOL
proto_TCP = pkt.ipv4.TCP_PROTOCOL
proto_OF = pkt.ipv4.TCP_PROTOCOL
handoverData = [ip_flow_handover , proto_UDP, port_flow_handover]