import uuid
import requests
import json
import logging
import ast
from array import array
from random import randint
from threading import Thread
from time import sleep
import time
import thread
from ryu.app.wsgi import ControllerBase, WSGIApplication, route
from ryu.base import app_manager
from ryu.controller import dpset, ofp_event
from ryu.controller import event
#from ryu.app.ofctl import api
from ryu.controller.handler import set_ev_cls, MAIN_DISPATCHER, CONFIG_DISPATCHER
from ryu.exception import RyuException
from ryu.lib import dpid as dpidlib
from ryu.lib import ofctl_v1_3 as ofctl
from ryu.lib.ovs import bridge
from ryu.lib.ovs import vsctl
from ryu.lib.packet import packet, udp, ether_types, in_proto
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import bfd
from ryu.lib.packet import arp
from ryu.lib.packet import udp
from ryu.ofproto.ether import ETH_TYPE_IP, ETH_TYPE_ARP
from ryu.lib.packet.arp import ARP_REQUEST, ARP_REPLY
from ryu.ofproto import ofproto_v1_3 as ofproto
from ryu.ofproto import ofproto_v1_3_parser as parser
from ryu.services.protocols.ovsdb import api as ovsdb
from ryu.services.protocols.ovsdb import event as ovsdb_event
from ryu.topology.event import EventSwitchEnter, EventSwitchLeave
from webob import Response
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
requests.packages.urllib3.disable_warnings()

path = "/sdnController"

LOG = logging.getLogger('ryu.app.contextupdater')

VM_on = False
VM_ip = None
i = 0						#general ID of each CPE/VCPE
j = 0						#ID of each 'border_bridge' (one in each VM)
VM_info = {}				#dict to save VMs info Ex: {ip address: system_id}
queue1 = []					#IP's list on buffer
queue2 = []					#system_id's list on buffer
b = 0						#buffer's index
port_out = None 			#VM's interface to end_node
ip_port_out = None 			
mac_port_out = None
tunnel_end = None
br_Pairs = {}				#dict of CPE-VCPE sets. Ex: {"cpe34": "vcpe34"}
data_base = {}				#general dict with info about all connected bridges
cont_FW = None
cont_DHCP = None
port_list = []				#list of ports, resulting from get_port_list()
token = {}
count_stack = 0
stack_stop = 0
mac_end_node = "fa:16:3e:ce:8d:75"
ip_end_node = "10.0.2.5"
ip_sdn_ctrl_VM_net = "10.0.1.2"	#ip of sdn controller of VMs network
vcpe_info = {}				#dict of some vcpe's info
br0_total_ports = {}		#dict of number of total ports of all border_bridges. Ex: {"br02": 3}
cpe_total_ports = {}		#dict of number of total ports of all cpe. Ex: {"cpe26": 7}

def command_method(method):
  def wrapper(self, req, *args, **kwargs):
	try:
	  if req.body:
		# We use ast.literal_eval() to parse request json body
		# instead of json.loads().
		# Because we need to parse binary format body
		# in send_experimenter().
		body = ast.literal_eval(req.body.decode('utf-8'))
	  else:
		body = {}
	except SyntaxError:
	  LOG.exception('Invalid syntax: %s', req.body)
	  return Response(status=400)

	# Invoke GTPTunnelController method
	try:
	  method(self, req, body, *args, **kwargs)
	  return Response(status=200)
	except ValueError:
	  LOG.exception('Invalid syntax: %s', req.body)
	  return Response(status=400)
  return wrapper


class sdnController(app_manager.RyuApp):
	
	OFP_VERSIONS = [ofproto.OFP_VERSION]

	_CONTEXTS = {
	'dpset': dpset.DPSet,
	'wsgi': WSGIApplication
	}

	def __init__(self, *args, **kwargs):
		super(sdnController, self).__init__(*args, **kwargs)
		self.dpset = kwargs['dpset']
		wsgi = kwargs['wsgi']
		self.data = {} #???
		self.data['dpset'] = self.dpset
		mapper = wsgi.mapper
		self.dp = 0
		# initialize mac address table
		self.mac_to_port = {}
		global this
		this = self

		wsgi.registory['updaterController'] = self.data
		url = path + '/add'
		mapper.connect('add_port', url, controller=updaterController,
						action='add_port', conditions=dict(method=['POST']))

		url = path + '/move'
		mapper.connect('move', url, controller=updaterController,
						action='move', conditions=dict(method=['POST']))

		url = path + '/show'
		mapper.connect('show', url, controller=updaterController,
						action='show', conditions=dict(method=['POST']))

		url = path + '/stack_ready'
		mapper.connect('stack_ready', url, controller=updaterController,
						action='stack_ready', conditions=dict(method=['POST']))
		
	@set_ev_cls(ovsdb_event.EventNewOVSDBConnection)
	def handle_new_ovsdb_connection(self, ev):
		system_id = ev.system_id
		address = ev.client.address
		global VM_on, i, j
		global VM_info
		global queue1, queue2
		global br0_total_ports

		self.logger.info(
			'New OVSDB connection from system-id=%s, address=%s',
			system_id, address)

		#to create a bridge pair [cpeX -> vcpeX], its essential that before a CPE is connected, already a VM is connected. Otherwise, CPE info is stored in a buffer 
		if ("192.168.94" in address[0]):			#check if system connected is a CPE
			self.logger.info("time1:  "+str(int(round(time.time() * 1000))))
			if VM_on == True:
				i+=1
				docker_stack(i, "deploy")				#stack deploy request
				link_config(address, system_id, i)		#all cpe-vcpe links configurations
			else:
				store_buffer(address, system_id)
		else:						
			VM_info[address[0]] = system_id		
			#check if this VM already has a 'br0'. If not, a 'br0' is created 
			for key,val in data_base.items():
				if "br0" in key and data_base[key]['datapath'].address[0] == address[0]:
					return
			j+=1
			br0 = "br0"+str(j)
			create_bridge(system_id, address[0], br0)
			set_controller(address[0], br0, ip_sdn_ctrl_VM_net)
			br0_total_ports[br0]=1
			
			
	@set_ev_cls(EventSwitchEnter)
	def _ev_switch_enter_handler(self, ev):
		#br_name = ev.msg.body
		global i, VM_on
		global queue1, queue2

		dp = ev.switch.dp
		dpid = ev.switch.dp.id

		self.logger.info(" ")
		self.logger.info('New bridge connection: %s' %ev.switch)
		
		#add flow with priority=0,actions=normal to every new bridge connection
		add_flow(ev.switch.dp, 0, parser.OFPMatch(), [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, [parser.OFPActionOutput(ofproto.OFPP_NORMAL)])], cookie=0, table_id=0, idle_timeout=0, flags=None, buffer_id=None)
		
		OVSDB_ADDR = 'tcp:'+ev.switch.dp.address[0]+':6640'
		br = bridge.OVSBridge(self.CONF, dpid, OVSDB_ADDR)
		br_name = br._get_bridge_name()								#get name of the bridge entered
		data_base[br_name]={'datapath':dp, 'address':dp.address[0]}
		
		update_data(br_name)
		self.logger.info(br_name)
		br0_on = 0
		for key,val in data_base.items():
			if "br0" in key:
				br0_on+=1

		if br0_on >= 2:
			VM_on = True								#only true when master_VM and slave_VM (at least) were already entered
			if len(queue1) > 0:							#if buffer is not empty, empty it
				x = 0
				while x < len(queue1):
					i+=1
					docker_stack(i, "deploy")		
					link_config(queue1[x], queue2[x], i)		
					del queue1[x]						#remove cpe info from buffer
					del queue2[x]
		
	@set_ev_cls(ofp_event.EventOFPPortDescStatsReply, MAIN_DISPATCHER)
	def port_desc_stats_reply_handler(self, ev):
		global data_base, br_Pairs
		global cont_ports
		br_ports = {}
		dpid = ev.msg.datapath
		lista = []
		br = None

		for key, val in data_base.items():
			for key2, val2 in val.items():
				if dpid == val2:
					br = key
					
		for p in ev.msg.body:
			lista.append(p)

		for j in range(len(lista)):
			br_ports[lista[j][2]] = {'port_no':lista[j][0],
									 'hw_addr':lista[j][1]}
		if br is not None:
			data_base[br].update({'ports':br_ports})

		
		#assure every bridges have all desired ports before setting flow rules
		aux = {}
		for key,val in br_Pairs.items():
		 	if val==br:
		 		br0 = vcpe_info[br]["br0"]
		 		p_fw = vcpe_info[br]["port_br0_fw"]
		 		aux = data_base[br0]['ports']
		 		if aux is None:
					continue
				else:
			 		if ('ports' in data_base[key].keys()) and ('ports' in data_base[val].keys()):
				 		if ('gre0' in data_base[key]['ports']) and (len(data_base[val]['ports']))>=4:
				 		 	for key2,val2 in aux.items():
								if p_fw == val2.get('port_no'):
						 		 	#self.logger.info("READY to Flows!")
						 		 	num = int(br[4:])
						 		 # 	for key1,val1 in data_base.items():
										# self.logger.info(key1)
										# self.logger.info(data_base[key1])
										# self.logger.info("........")
									#gratuitous arp sended to end_node, everytime flow rules are updated
									ans = arp_packet(ARP_REPLY, mac_port_out, vcpe_info[br]["ip_fw"],"ff:ff:ff:ff:ff:ff", ip_end_node)
									actions = [parser.OFPActionOutput(1)]
									out = parser.OFPPacketOut(datapath=data_base[br0]['datapath'], buffer_id=ofproto.OFP_NO_BUFFER, in_port=ofproto.OFPP_CONTROLLER, actions=actions, data=ans)
									data_base[br0]['datapath'].send_msg(out)
									# self.logger.info("gratuitous arp reply sended!"+str(int(round(time.time() * 1000))))
				 		 			setting_flows(num, br)
						

	@set_ev_cls(ofp_event.EventOFPPortStateChange)
	def _ev_switch_add_port(self, ev):
		#update data_base only when a port is removed
		if ev.reason == 1:
			ev.datapath.send_msg(parser.OFPPortDescStatsRequest(ev.datapath, 0))
			time.sleep(0.5)				

	#when a bridge receives an arp request, an arp reply is generated to the incoming port
	@set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
	def _packet_in_handler(self, ev):
		msg = ev.msg
		datapath = msg.datapath
		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser
		in_port = msg.match['in_port']
		global data_base
		global mac_src
		
		aux = {}
		aux2 = {}
		for key,val in data_base.items():
			if val.get('datapath') == datapath:
				#update_data(key)
				aux = val.get('ports')
				if aux is None:
					continue
				else:
					for key2,val2 in aux.items():
						aux2 = aux[key2]
						if aux2['port_no']==in_port:
							mac_src = aux2['hw_addr']


		arp_pkt = arp_parse(msg.data)
		ans = arp_packet(ARP_REPLY, mac_src, arp_pkt.dst_ip, arp_pkt.src_mac, arp_pkt.src_ip)
		actions = [parser.OFPActionOutput(in_port)]
		out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER, in_port=ofproto.OFPP_CONTROLLER, actions=actions, data=ans)
		datapath.send_msg(out)
	

class updaterController(ControllerBase):
	def __init__(self, req, link, data, **config):
		super(updaterController, self).__init__(req, link, data, **config)
		self.dpset = data['dpset']
		self.ovsdb_addr = None
	
		ret = 0;
		
	@command_method
	def show(self, req, body, *args, **kwargs):
		global i 

		# for key,val in data_base.items():
		# 	this.logger.info(key)
		# 	this.logger.info(data_base[key])


		br0 = body["br0"]

		ans = arp_packet(ARP_REPLY, mac_port_out, body["ip_fw"],"ff:ff:ff:ff:ff:ff", ip_end_node)

		actions = [parser.OFPActionOutput(1)]
		out = parser.OFPPacketOut(datapath=data_base[br0]['datapath'], buffer_id=ofproto.OFP_NO_BUFFER, in_port=ofproto.OFPP_CONTROLLER, actions=actions, data=ans)

		data_base[br0]['datapath'].send_msg(out)


	@command_method
	def move(self, req, body, *args, **kwargs):
		global count_stack, data_base, stack_stop
		global priority, stacks
		global VM_ip, VM_info
		global port_out, mac_port_out, tunnel_end
		global vcpe_info, cpe_total_ports
		br_to_move = None

		#this.logger.info(time.ctime())
		this.logger.info("handover (tm1) "+str(int(round(time.time() * 1000))))
		lista = []
		
		ans = udp_packet(67, "bb:bb:bb:bb:bb:bb", "10.10.10.10","ff:ff:ff:ff:ff:ff", "20.20.20.20")
		actions = [parser.OFPActionOutput(1)]
		out = parser.OFPPacketOut(datapath=data_base[vcpe_info['vcpe1']['br0']]['datapath'], buffer_id=ofproto.OFP_NO_BUFFER, in_port=ofproto.OFPP_CONTROLLER, actions=actions, data=ans)
		data_base[vcpe_info['vcpe1']['br0']]['datapath'].send_msg(out)


		body_list = body["high_load"].get("nodes")
		full_node = body_list[0]
		#lista.append(body["high_load"]["nodes"])
		
		for key,val in vcpe_info.items():
			# if val.get('node') is None:
			# 	continue
			if val.get('node') == full_node:
				lista.append(key)

		#escolher o vcpe de maior prioridade:
		c = 1
		for i in range(len(lista)):
			for key,val in vcpe_info.items():
				if key == lista[i] and val.get('priority') >= c:
					br_to_move = key
					c = val
		
		if br_to_move is None:
			#this.logger.info("there is any vcpe on that VM !!")
			return

	
		del data_base[br_to_move]['ports']
		
		old_port_br0_fw = vcpe_info[br_to_move]['port_br0_fw']
		old_br0 = vcpe_info[br_to_move]['br0']
		old_addr = data_base[br_to_move]['datapath'].address[0]
		old_stack = vcpe_info[br_to_move]['stack']
		old_stack_id = old_stack[5:]
		num = int(br_to_move[4:])	#num_id da vcpe
		num_stack = "0"+str(old_stack_id)
		# #criar docker stack e esperar que esteja criada...
		docker_stack(num_stack, "deploy")
		this.logger.info("stack requested! (tm2) "+str(int(round(time.time() * 1000))))
		actual_count_stack = count_stack
		while (count_stack != (actual_count_stack+2)):
			this.logger.info('waiting...')
			#this.logger.info(actual_count_stack)
			#this.logger.info(count_stack)
			time.sleep(5)

		for key,val in br_Pairs.items():
			if br_to_move == val:
				this_cpe = key

		for key,val in data_base.items():
			if "br0" in key and (data_base[key]['datapath'].address[0] == VM_ip):
					this_br0 = key

		# #this.logger.info(VM_ip)
		# #criar nova bridge
		create_bridge(VM_info[VM_ip], VM_ip, br_to_move)
		set_controller(VM_ip, br_to_move, ip_sdn_ctrl_VM_net)
		vcpe_info[br_to_move].update({"stack":'stack'+str(num_stack), "node": node_name, "br0": this_br0})
					
		add_port(VM_ip, this_br0, port_out)		#ens7 port na br0X
		
	
		# #criar portas na nova bridge
		add_tunnel_port(VM_ip, br_to_move, 'gre0'+str(num), data_base[this_cpe]['datapath'].address[0])
		add_tunnel_port(VM_ip, br_to_move, 'gre1'+str(num), 'flow')

		# #add cont ports na vcpe
		add_cont_ports(num, br_to_move, this_br0)
			
		# #deixar cpe so com uma "gre0"
		# del_port(data_base[this_cpe]['datapath'].address[0], this_cpe, 'gre0')
		add_tunnel_port(data_base[this_cpe]['datapath'].address[0], this_cpe, 'gre'+num_stack, tunnel_end)
		# #del_port(data_base[this_cpe]['datapath'].address[0], this_cpe, 'gre00')
		this.logger.info("tunnels updated! (tm3) "+str(int(round(time.time() * 1000))))
		cpe_total_ports[this_cpe]+=1

		update_data(this_br0)
		update_data(this_cpe)
		update_data(br_to_move)
		
		#this.logger.info(vcpe_info)


		for key,val in data_base[this_cpe]['ports'].items():
			if val.get('port_no') == (cpe_total_ports[this_cpe]-1):
				del_port(data_base[this_cpe]['datapath'].address[0], this_cpe, key)

		
		delete_bridge(old_addr, br_to_move)
		this.logger.info("bridge deleted! (tm5) "+str(int(round(time.time() * 1000))))
		# this.logger.info("old br0  : "+old_br0)
		#del_port(data_base[old_br0]['datapath'].address[0], old_br0, 'patch0'+str(num))
		for key,val in data_base[old_br0]['ports'].items():
			if val.get('port_no') == old_port_br0_fw:
				del_port(data_base[old_br0]['datapath'].address[0], old_br0, key)
				this.logger.info("delete old port fw to br0! (tm6) "+str(int(round(time.time() * 1000))))

		# #delete old stack (secalhar e preciso criar um dict(vcpeX: stackX) para poder apagar as stack)
		docker_stack(old_stack_id, "remove")
		this.logger.info("stack remove! (tm7) "+str(int(round(time.time() * 1000))))
		actual_stack_stop = stack_stop
		while (stack_stop != (actual_stack_stop+2)):
			this.logger.info('waiting...')
			this.logger.info(actual_stack_stop)
			this.logger.info(actual_stack_stop)
			time.sleep(5)
		
		update_data(old_br0)
		#del flow old_br0
		
		this.logger.info("Move terminated!"+str(int(round(time.time() * 1000))))
		#this.logger.info(time.ctime())

	#containers criados!
	@command_method
	def stack_ready(self, req, body, *args, **kwargs):
		global VM_ip, tunnel_end
		global port_out, ip_port_out, mac_port_out
		global cont_FW, cont_DHCP
		global count_stack, data_base
		global node_name
		global stack_stop

		if body["action"] == "start":
			count_stack += 1
			port_out = body["vm"]["target_int_name"]
			ip_port_out = body["vm"]["target_int_ip_address"]
			mac_port_out = body["vm"]["target_int_mac_addr"]
			node_name = body["container"]["node_name"]
			tunnel_end = body["vm"]["ext_int_ip_address"]
			VM_ip = body["vm"]["ctrl_nic_ip_address"]
			cont_name = body["container"]["name"]			
			if "firewall" in cont_name:
				cont_FW = cont_name
			elif "dhcp" in cont_name:
				cont_DHCP = cont_name
			this.logger.info("stacks created (time3): "+str(int(round(time.time() * 1000))))
			

		if body["action"] == "stop":
			stack_stop += 1
			this.logger.info("stacks removed (tm8): "+str(int(round(time.time() * 1000))))

		


def add_flow(datapath, priority, match, inst, cookie=0, table_id=0, idle_timeout=0, flags=None, buffer_id=None):

	if buffer_id:
		if flags:
			mod = parser.OFPFlowMod(datapath=datapath, cookie=cookie, table_id=table_id, idle_timeout=idle_timeout, buffer_id=buffer_id, priority=priority, flags=flags, match=match, instructions=inst)
		else:
			mod = parser.OFPFlowMod(datapath=datapath, cookie=cookie, table_id=table_id, idle_timeout=idle_timeout, buffer_id=buffer_id, priority=priority, match=match, instructions=inst)
	else:
		if flags:
			mod = parser.OFPFlowMod(datapath=datapath, cookie=cookie, table_id=table_id, idle_timeout=idle_timeout,	priority=priority, flags=flags, match=match, instructions=inst)
		else:
			mod = parser.OFPFlowMod(datapath=datapath, cookie=cookie, table_id=table_id, idle_timeout=idle_timeout,	priority=priority, match=match, instructions=inst)

	datapath.send_msg(mod)

def del_flow(datapath, match, table_id=0, buffer_id=None):
	inst = []

	if buffer_id:
		mod = parser.OFPFlowMod(datapath=datapath, table_id=table_id, buffer_id=buffer_id, match=match, instructions=inst, command=ofproto.OFPFC_DELETE, out_port=ofproto.OFPP_ANY, out_group=ofproto.OFPG_ANY)
	else:
		mod = parser.OFPFlowMod(datapath=datapath, table_id=table_id, match=match, instructions=inst, command=ofproto.OFPFC_DELETE, out_port=ofproto.OFPP_ANY, out_group=ofproto.OFPG_ANY)

	datapath.send_msg(mod)

def udp_packet(out_port, src_mac, src_ip, dst_mac, dst_ip):
	
	ethertype = 0x07c3
	e = ethernet.ethernet(dst_mac, src_mac, ethertype)
	ip = ipv4.ipv4(src=src_ip, dst=dst_ip)
	send_time = time.time()*100%100000
	u = udp.udp(src_port=out_port,dst_port=send_time)

	p = packet.Packet()
	p.add_protocol(e)
	p.add_protocol(ip)
	p.add_protocol(u)
	#p.add_protocol(out_port)
	p.add_protocol(time.time())
	p.serialize()
	return p

def arp_packet(opcode, src_mac, src_ip, dst_mac, dst_ip):
	"""
	Generate ARP packet with ethernet encapsulated.
	"""
	# Generate ethernet header first.
	pkt = packet.Packet()
	eth_pkt = ethernet.ethernet(dst_mac, src_mac, ETH_TYPE_ARP)
	pkt.add_protocol(eth_pkt)

		# Use IPv4 ARP wrapper from packet library directly.
	arp_pkt = arp.arp_ip(opcode, src_mac, src_ip, dst_mac, dst_ip)
	pkt.add_protocol(arp_pkt)
	pkt.serialize()

	return pkt.data 

def arp_parse(data):
	"""
	Parse ARP packet, return ARP class from packet library.
	"""
	# Iteratize pkt
	pkt = packet.Packet(data)
	i = iter(pkt)
	eth_pkt = next(i)
		# Ensure it's an ethernet frame.
	assert isinstance(eth_pkt, ethernet.ethernet)

	arp_pkt = next(i)
	if not isinstance(arp_pkt, arp.arp):
		raise ARPPacket.ARPUnknownFormat()

	if arp_pkt.opcode not in (ARP_REQUEST, ARP_REPLY):
		raise ARPPacket.ARPUnknownFormat(
			msg='unsupported opcode %d' % arp_pkt.opcode)

	if arp_pkt.proto != ETH_TYPE_IP:
		raise ARPPacket.ARPUnknownFormat(
			msg='unsupported arp ethtype 0x%04x' % arp_pkt.proto)

	return arp_pkt

def store_buffer(address, system_id):
	global b
	global queue1
	global queue2
	queue1.insert(b, address)
	queue2.insert(b, system_id)
	b = b + 1
	
def docker_stack(num, action):
	global token

	if not token or token.get("expires") < time.time():
		token = get_token()

	_id = token.get("id")

	stack_name = 'stack'+str(num)

	payload1 = {
		"member_vnf_index": "2",
		"primitive": "stack-deploy",
		"primitive_params": {
			"docker_compose_url": "http://192.168.85.28/docker/containers/docker-compose.yml",
			"stack_name": stack_name
		}
	}

	payload2 = {
		"member_vnf_index": "2",
		"primitive": "stack-remove",
		"primitive_params": {
			"stack_name": stack_name
		}
	}

	headers = {
		'Accept': 'application/json',
		'Authorization': 'Bearer '+_id,
	}


	response = requests.get('https://192.168.85.148:9999/osm/nslcm/v1/ns_instances', headers=headers, verify=False)
	osm_data = []
	osm_data = json.loads(response.text)
	
	
	for i in range(len(osm_data)):
		for key,val in osm_data[i].items():
				if val == "vcpe":
					aux=osm_data[i].get("id")
					break

	url_docker_stack = 'https://192.168.85.148:9999/osm/nslcm/v1/ns_instances/'+aux+'/action'			
	
	if action == "deploy":
		r = requests.post(url_docker_stack, data=json.dumps(payload1), headers=headers, verify=False)
	else:
		r = requests.post(url_docker_stack, data=json.dumps(payload2), headers=headers, verify=False)

def link_config(address, system_id, num):
	#this.logger.info("------")
	#this.logger.info("BRIDGES CONFIG:")
	global VM_ip, count_stack
	global br_Pairs, VM_info
	global tunnel_end, data_base
	global port_out, mac_port_out
	global vcpe_info, cpe_total_ports
	
	this.logger.info("pedido criar stack (time2): "+str(int(round(time.time() * 1000))))
	actual_count_stack = count_stack
	while (count_stack != (actual_count_stack+2)):					#waiting for stack deployment be ready
		#this.logger.info('waiting...')
		#this.logger.info(actual_count_stack)
		#this.logger.info(count_stack)
		time.sleep(5)
			
	
	for key,val in data_base.items():
		if "br0" in key and (data_base[key]['datapath'].address[0] == VM_ip):
			br0 = key

	br_Pairs['cpe'+str(num)] = 'vcpe'+str(num)

	bridge = 'cpe'+str(num)

	vcpe_info[br_Pairs[bridge]]={}
	controller_ip = get_ip()								#sdn_ctrl IP of the external network

	#create bridge on CPE
	get_br_list(address[0])
	if(len(br_list) == 0):
		create_bridge(system_id, address[0], bridge)
		set_controller(address[0], bridge, str(controller_ip))
	else:
		return

	p = randint(1, 10)										#priority number of vcpe
	#create corresponding brigde on VM
	create_bridge(VM_info[VM_ip], VM_ip, br_Pairs[bridge])
	set_controller(VM_ip, br_Pairs[bridge], ip_sdn_ctrl_VM_net)
	this.logger.info("create new bridges: (time4)"+str(int(round(time.time() * 1000))))


	add_port(VM_ip, br0, port_out)							#'br0' interface to end_node (usually ens7)
	this.logger.info("attach port_out(time5): "+str(int(round(time.time() * 1000))))

	#tunnel ports on CPE
	add_tunnel_port(address[0], bridge, 'gre1', 'flow')
	add_tunnel_port(address[0], bridge, 'gre0', tunnel_end)
	cpe_total_ports[bridge] = 2

	#tunnel ports on VM
	add_tunnel_port(VM_ip, br_Pairs[bridge], 'gre0'+str(num), address[0])
	add_tunnel_port(VM_ip, br_Pairs[bridge], 'gre1'+str(num), 'flow')		
	this.logger.info("create tunnel ports: (time6)"+str(int(round(time.time() * 1000))))

	add_cont_ports(num, br_Pairs[bridge], br0)				#attach containers to vcpe bridge
	this.logger.info("attach containers to bridges(time7): "+str(int(round(time.time() * 1000))))
	

	vcpe_info[br_Pairs[bridge]].update({"priority": p,
								 "stack": 'stack'+str(num),
								 "br0": br0,
								 "node": node_name
								})
	this.logger.info(vcpe_info)

def update_data(bridge):

	data_base[bridge]['datapath'].send_msg(parser.OFPPortDescStatsRequest(data_base[bridge]['datapath'], 0))

def setting_flows(num, vcpe):
	global data_base, br_Pairs
	
	#this.logger.info("flows update begins"+str(int(round(time.time() * 1000))))

	for key, val in br_Pairs.items():
		if val == vcpe:
			cpe = key
	 		cpe_flows(num, cpe)
	 		vcpe_flows(num, vcpe)

	br0_flows(num, vcpe)

def br0_flows(num, vcpe):
	global data_base, vcpe_info
	global port_out, ip_port_out, mac_port_out

	br0 = vcpe_info[vcpe]["br0"]

	DST_NET = ip_port_out[:7]+'0/24'
	
	datapath = data_base[br0]['datapath']
	port_out_no = data_base[br0]['ports'][port_out]['port_no']
	ip_fw = vcpe_info[vcpe]['ip_fw'] 
	p_fw = vcpe_info[vcpe]['port_br0_fw']
	mac_br0= data_base[br0]['ports'][br0]['hw_addr']
	
	add_flow(datapath, 1, parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,in_port=port_out_no,ipv4_dst=ip_fw), 
		[parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, 
		[parser.OFPActionSetField(eth_src=mac_br0), parser.OFPActionSetField(eth_dst=vcpe_info[vcpe]['mac_c_fw']), parser.OFPActionOutput(p_fw)])], cookie=0, table_id=0, idle_timeout=0, flags=None, buffer_id=None)

	add_flow(datapath, 1, parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,in_port=p_fw,ipv4_dst=DST_NET), 
		[parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, 
		[parser.OFPActionSetField(eth_dst=mac_end_node),parser.OFPActionOutput(int(port_out_no))])], cookie=0, table_id=0, idle_timeout=0, flags=None, buffer_id=None)

	add_flow(datapath, 1, parser.OFPMatch(eth_type=ether_types.ETH_TYPE_ARP,arp_op=arp.ARP_REQUEST), 
				[parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, 6633)])], cookie=0, table_id=0, idle_timeout=0, flags=None, buffer_id=None)

	this.logger.info("flows created (all setted up)(timer8): "+str(int(round(time.time() * 1000))))
	# docker_stack(1, "remove")
	# # #time.sleep(20)
	# delete_bridge("192.168.94.155", "cpe1")
	# delete_bridge("10.0.1.8", "vcpe1")
	# delete_bridge("10.0.1.8", "br01")
	# delete_bridge("10.0.1.8", "br02")
	# delete_bridge("10.0.1.12", "br01")
	# delete_bridge("10.0.1.12", "br02")
	# delete_bridge("10.0.1.12", "vcpe1")
	# this.logger.info("all deleted!")

	ans = udp_packet(5001, "aa:aa:aa:aa:aa:aa", "10.10.10.10","ff:ff:ff:ff:ff:ff", "20.20.20.20")
	actions = [parser.OFPActionOutput(1)]
	out = parser.OFPPacketOut(datapath=data_base[vcpe_info['vcpe1']['br0']]['datapath'], buffer_id=ofproto.OFP_NO_BUFFER, in_port=ofproto.OFPP_CONTROLLER, actions=actions, data=ans)
	data_base[vcpe_info['vcpe1']['br0']]['datapath'].send_msg(out)

def cpe_flows(num, cpe):
	global data_base, ip_port_out
	global cpe_total_ports

	DST_NET = ip_port_out[:7]+'0/24'
	mac_cpe = data_base[cpe]['ports'][cpe]['hw_addr']

	gre0 = cpe_total_ports[cpe]

	add_flow(data_base[cpe]['datapath'], 2, parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,ipv4_dst="10.0.0.11"), 
		[parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, [parser.OFPActionOutput(gre0)])], cookie=0, table_id=0, idle_timeout=0, flags=None, buffer_id=None)

	add_flow(data_base[cpe]['datapath'], 1, parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,ipv4_dst="10.0.0.0/24"), 
		[parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, [parser.OFPActionSetField(eth_dst=mac_cpe), parser.OFPActionOutput(ofproto.OFPP_NORMAL)])], cookie=0, table_id=0, idle_timeout=0, flags=None, buffer_id=None)

	add_flow(data_base[cpe]['datapath'], 1, parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,ipv4_dst=DST_NET), 
		[parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, [parser.OFPActionOutput(gre0)])], cookie=0, table_id=0, idle_timeout=0, flags=None, buffer_id=None)

	add_flow(data_base[cpe]['datapath'], 1, parser.OFPMatch(eth_type=ether_types.ETH_TYPE_ARP,arp_op=arp.ARP_REQUEST), 
				[parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, 6633)])], cookie=0, table_id=0, idle_timeout=0, flags=None, buffer_id=None)

def vcpe_flows(num, vcpe):
	global data_base, cont_ports, ip_port_out

	DST_NET = ip_port_out[:7]+'0/24'
	p_fw = 3#cont_ports[vcpe]['fw']						#number of the port connected to firewall container (normally 3)
	mac_fw = "02:00:00:00:00:fa"
	p_dhcp = 4#cont_ports[vcpe]['dhcp']					##number of the port connected to dhcp container (normally 4)
	gre0 = data_base[vcpe]['ports']['gre0'+str(num)]['port_no']
	mac = data_base[vcpe]['ports'][vcpe]['hw_addr']

	add_flow(data_base[vcpe]['datapath'], 2, parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,in_port=p_dhcp,ipv4_dst="10.0.0.0/24"), 
		[parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, [parser.OFPActionOutput(gre0)])], cookie=0, table_id=0, idle_timeout=0, flags=None, buffer_id=None)

	add_flow(data_base[vcpe]['datapath'], 2, parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,ipv4_dst="10.0.0.11"), 
		[parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, [parser.OFPActionOutput(p_dhcp)])], cookie=0, table_id=0, idle_timeout=0, flags=None, buffer_id=None)

	add_flow(data_base[vcpe]['datapath'], 1, parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,in_port=gre0,ipv4_dst=DST_NET), 
		[parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, 
		[parser.OFPActionSetField(eth_src=mac),parser.OFPActionSetField(eth_dst=mac_fw), parser.OFPActionOutput(p_fw)])], cookie=0, table_id=0, idle_timeout=0, flags=None, buffer_id=None)

	add_flow(data_base[vcpe]['datapath'], 1, parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,in_port=p_fw,ipv4_dst="10.0.0.0/24"), 
		[parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, [parser.OFPActionOutput(gre0)])], cookie=0, table_id=0, idle_timeout=0, flags=None, buffer_id=None)

	add_flow(data_base[vcpe]['datapath'], 1, parser.OFPMatch(eth_type=ether_types.ETH_TYPE_ARP,arp_op=arp.ARP_REQUEST), 
				[parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, 6633)])], cookie=0, table_id=0, idle_timeout=0, flags=None, buffer_id=None)

def add_cont_ports(num, br_vcpe, br0_name):
	global cont_ports, data_base
	global cont_FW, cont_DHCP
	global token
	global VM_ip
	global vcpe_info, br0_total_ports

	url = 'http://'+VM_ip+':5004/setup_c_port'
	url2 = 'http://'+VM_ip+':5004/setup_bridge'
	
	gw = "10.0.0.1"					#vcpe IP

	payload_FW = {
	   "br_name": br_vcpe,
	   "c_name": cont_FW,
	   "ip_address": "10.0.0.20/24",
	   "mac_address": "02:00:00:00:00:fa",
	   "c_iface": "eth0",
	   "gateway": gw 				
	}

	payload_DHCP = {
	   "br_name": br_vcpe,
	   "c_name": cont_DHCP,
	   "ip_address": "10.0.0.11/24",
	   "mac_address": "02:00:00:00:00:dc",
	   "c_iface": "eth0", 
	   "gateway": gw				
	}

	x = int(num)+20
	ip_c_fw = ip_port_out[0:7]+str(x)					#firewall container IP for exterior side (Ex: in vcpe35, packets come out from firewall container with 11.11.11.55, if end_node network is 11.11.11.0/24)
	x = str(randint(1111111111, 9999999999))			#generating a random mac_addr for firewall container exterior interface
	mac_c_fw = '02:'+x[0:2]+':'+x[2:4]+':'+x[4:6]+':'+x[6:8]+':'+x[8:]

	payload_FW_br0 = {
	   "br_name": br0_name,
	   "c_name": cont_FW,
	   "ip_address": ip_c_fw+'/24',
	   "mac_address": mac_c_fw,
	   "c_iface": "eth1", 
	   "gateway": ip_port_out 							#border_bridge IP
	}
	#this.logger.info(br0_total_ports)
	br0_total_ports[br0_name]+=1
	vcpe_info[br_vcpe].update({'ip_fw':ip_c_fw, 'mac_c_fw':mac_c_fw, "port_br0_fw": br0_total_ports[br0_name]})
	#this.logger.info(br0_total_ports)

	payload_vcpe = {
		"vcpe_name": br_vcpe,
		"br0_name": br0_name,
		"vcpe_ip_address": gw+'/24',
		"br0_ip_address": ip_port_out+'/24'
	}
	
	if token==None or token.get("expires") < time.time():
		token = get_token()

	_id = token.get("id")


	headers = {
		'Accept': 'application/json',
		'Authorization': 'Bearer '+_id,
	}

	r01 = requests.post(url2, data=json.dumps(payload_vcpe), headers=headers, verify=False)
	this.logger.info(r01.text)
	
	r1 = requests.post(url, data=json.dumps(payload_FW), headers=headers, verify=False)
	
	r2 = requests.post(url, data=json.dumps(payload_DHCP), headers=headers, verify=False)

	r3 = requests.post(url, data=json.dumps(payload_FW_br0), headers=headers, verify=False)
	update_data(br0_name)
	
def create_bridge(system_id, address, bridge):
	if ovsdb.bridge_exists(this, system_id, bridge):
		pass
	else:
		OVSDB_ADDR = 'tcp:'+address+':6640'
		ovs_vsctl = vsctl.VSCtl(OVSDB_ADDR)
		command = vsctl.VSCtlCommand('add-br', (bridge,))
		ovs_vsctl.run_command([command])
		
def delete_bridge(address, bridge):

	OVSDB_ADDR = 'tcp:'+address+':6640'
	ovs_vsctl = vsctl.VSCtl(OVSDB_ADDR)
	command = vsctl.VSCtlCommand('del-br', (bridge,))
	ovs_vsctl.run_command([command])
	
def get_token():
	global token
	
	headers = {
		'Accept': 'application/json',
		'Content-Type': 'application/json',
	}
	data = '{\n    "username": "vieiratiago",\n    "password": "xanfrado99",\n    "project_id": "5gcontact"\n}'
	response = requests.post('https://192.168.85.148:9999/osm/admin/v1/tokens', headers=headers, data=data, verify=False)

	token = json.loads(response.text)
	return token

def get_ip():
	global token

	if token==None or token.get("expires") < time.time():
		token = get_token()

	_id = token.get("id")


	headers2 = {
		'Accept': 'application/json',
		'Authorization': 'Bearer '+_id,
	}

	response2 = requests.get('https://192.168.85.148:9999/osm/nslcm/v1/ns_instances/', headers=headers2, verify=False)
	osm_data = []
	osm_data = json.loads(response2.text)

	
	for i in range(len(osm_data)):
		for key,val in osm_data[i].items():
				if val == "vcpe":
					id=osm_data[i].get("id")
					break

	response2 = requests.get('https://192.168.85.148:9999/osm/nslcm/v1/vnfrs/', headers=headers2, verify=False)
	osm_data = []
	osm_data = json.loads(response2.text)

	for i in range(len(osm_data)):
		for key,val in osm_data[i].items():
			if osm_data[i]['nsr-id-ref']==id and osm_data[i]['vnfd-ref'] == "sdn-ctrl":
				aux=osm_data[i].get("vdur")
				break

	interfaces = aux[0].get("interfaces")

	for j in range(len(interfaces)):
		for key,val in interfaces[j].items():
			if val == "ext-net":
				ip=interfaces[j].get("ip-address")

	return ip

def add_port(address, bridge, port_name):
	#mechanism to check if the port already exists on that bridge
	get_port_list(address, bridge)
	p = 0
	while(p < len(port_list)):
		if port_name == port_list[p]:
			return
		else:
			p+=1

	OVSDB_ADDR = 'tcp:'+address+':6640'
	ovs_vsctl = vsctl.VSCtl(OVSDB_ADDR)
	command = vsctl.VSCtlCommand('add-port', (bridge, port_name))
	ovs_vsctl.run_command([command])

def del_port(address, bridge, port_name):

	OVSDB_ADDR = 'tcp:'+address+':6640'
	ovs_vsctl = vsctl.VSCtl(OVSDB_ADDR)
	command = vsctl.VSCtlCommand('del-port', (bridge, port_name))
	ovs_vsctl.run_command([command])

def add_tunnel_port(address, bridge, port_name, remote_ip, local_ip=None, key='flow', ofport=None):
	##mechanism to check if the port already exists on that bridge
	get_port_list(address, bridge)
	p = 0
	while(p < len(port_list)):
		if port_name == port_list[p]:
			return
		else:
			p+=1
	
	tunnel_type = 'gre'

	options = 'remote_ip=%(remote_ip)s' % locals()
	if key:
		options += ',key=%(key)s' % locals()
	if local_ip:
		options += ',local_ip=%(local_ip)s' % locals()
 
	args = ['Interface', port_name, 'type=%s' % tunnel_type, 'options:%s' % options]
	if ofport:
		args.append('ofport_request=%(ofport)s' % locals())
	
	OVSDB_ADDR = 'tcp:'+address+':6640'
	ovs_vsctl = vsctl.VSCtl(OVSDB_ADDR)
	command_add = vsctl.VSCtlCommand('add-port', (bridge, port_name))
	command_set = vsctl.VSCtlCommand('set', args)
	ovs_vsctl.run_command([command_add, command_set])

def get_port_list(address, bridge):
	global port_list
	port_list = []
	OVSDB_ADDR = 'tcp:'+address+':6640'
	ovs_vsctl = vsctl.VSCtl(OVSDB_ADDR)
	command = vsctl.VSCtlCommand('list-ports', (bridge, ))
	ovs_vsctl.run_command([command])
	#return command.result
	port_list = command.result

def get_br_list(address):
	global br_list

	OVSDB_ADDR = 'tcp:'+address+':6640'
	ovs_vsctl = vsctl.VSCtl(OVSDB_ADDR)
	command = vsctl.VSCtlCommand('list-br')
	ovs_vsctl.run_command([command])
	#return command.result
	br_list = command.result

def set_controller(address, bridge, controller_ip):
	controller_ip = 'tcp:'+controller_ip+':6633'

	OVSDB_ADDR = 'tcp:'+address+':6640'
	ovs_vsctl = vsctl.VSCtl(OVSDB_ADDR)
	command = vsctl.VSCtlCommand('set-controller', (bridge, controller_ip))
	ovs_vsctl.run_command([command])





