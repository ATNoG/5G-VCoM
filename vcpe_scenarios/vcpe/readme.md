
# An integration of OSM with a vCPE architecture
under development

# 5G Contact Docker Swarm Events 
This component in under the folder "5gc_docker_events" and aims to send notification to a pre-configured set of endpoints.
Currently it only supports notifications of creation and delete of docker container in the docker swearm.

This component is divided in two sub-components named "docker_events_collector" and "docker_events_notifier". Each of them has a YAML config file, this config file is detailed below.
"docker_events_collector" config file example:
```
master:
  ip: 192.168.2.2
  port: 5001
slave:
  ext_nic: ens4
  target_nic: ens7
```
"docker_events_collector" is divided in two sections. One that holds information about docker swarm master called "master" and another one called "slave" that have information related with the current node.
The section named "master" has the IP address and port of the "docker_events_notifier" host and the section "slave" holds the NIC name where the target IP address is associated.

"docker_events_notifier" has the following structure:
```
port: 5001
consumers:
  - 'http://host1_ip:host1_port'
  - 'http://host2_ip:host2_port'
```
This file has one attribute called "port", which is the port where the notifier will be listening for collector requests. There is also a list called "consumers" where each entry corresponds to the URL endpoint of a notification consumer.
Two notification payload examples are demonstrated below, one is related with container start and another with container stop.

Container start:
``` 
{
  "action": "start",
  "container": {
    "id": "244894e0e679ac783fe34ee92953ca6d2304b8aabc05941684c2882beb67ea58",
    "name": "recursing_chaplygin.1.v2pg27tfh3lhq46x4k9gxr12t",
    "node_name": "isp-2-swarmc-master-vdu-1"
  },
  "vm": {
    "ext_int_ip_address": "192.168.85.101",
    "ctrl_nic_ip_address": "10.0.1.6",
    "target_int_ip_address": "10.2.0.1",
    "target_int_name": "ens7",
    "target_int_mac_addr": "fa:16:3e:ef:82:58"
  },
  "time": 1552565643
}
```

Container stop:
```
{
  "action": "stop",
  "container": {
    "id": "244894e0e679ac783fe34ee92953ca6d2304b8aabc05941684c2882beb67ea58",
    "name": "recursing_chaplygin.1.v2pg27tfh3lhq46x4k9gxr12t",
    "node_name": "isp-2-swarmc-master-vdu-1"
  },
  "vm": {
    "ext_int_ip_address": "192.168.85.101",
    "ctrl_nic_ip_address": "10.0.1.6",
    "target_int_ip_address": "10.2.0.1",
    "target_int_name": "ens7",
    "target_int_mac_addr": "fa:16:3e:ef:82:58"
  },
  "time": 1552566015
}
```

An endpoint was created to retrieve available nodes in docker swarm. The endpoint is:
"http://<ip_address_of_master>:5001/nodes"
It returns a list with the current nodes available. Example payload:
```
["isp-2-swarmc-master-vdu-1", "isp-2-swarmc-slave-vdu-1"]
```
