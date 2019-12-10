import os
import subprocess
import requests
import json

from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
requests.packages.urllib3.disable_warnings()

def get_ip():
	headers = {
	    'Accept': 'application/json',
	    'Content-Type': 'application/json',
	}
	data = '{\n    "username": "vieiratiago",\n    "password": "xanfrado99",\n    "project_id": "5gcontact"\n}'
	response = requests.post('https://192.168.85.148:9999/osm/admin/v1/tokens', headers=headers, data=data, verify=False)
	token = {}
	token = json.loads(response.text)

	_id = token.get("id")


	headers2 = {
	    'Accept': 'application/json',
	    'Authorization': 'Bearer '+_id,
	}

	response2 = requests.get('https://192.168.85.148:9999/osm/nslcm/v1/vnfrs/', headers=headers2, verify=False)
	osm_data = []
	osm_data = json.loads(response2.text)

	for i in range(len(osm_data)):
		for key,val in osm_data[i].items():
			if (val == "sdn-ctrl"):
				aux=osm_data[i].get("vdur")
				#print(aux)
				if "vcpe" in aux[0].get("name"):
					interfaces = aux[0].get("interfaces")
					break	


	for j in range(len(interfaces)):
		for key,val in interfaces[j].items():
			if val == "ext-net":
				ip=interfaces[j].get("ip-address")

	#return ip
	for i in range(len(osm_data)):
                for key,val in osm_data[i].items():
                        if val == "swarmc":
                                aux2=osm_data[i].get("vdur")
                                break

	interfaces2 = aux2[0].get("interfaces")

	for j in range(len(interfaces2)):
                for key,val in interfaces2[j].items():
                        if val == "target-vld":
                                ip_end_node=interfaces2[j].get("ip-address")

	nw_end_node = ip_end_node[:7]+'0/24'
	#print(nw_end_node)
	subprocess.call(['bash','/etc/set-manager.sh',ip])
	subprocess.call(['bash','/etc/cpe_conf.sh',nw_end_node])

get_ip()
