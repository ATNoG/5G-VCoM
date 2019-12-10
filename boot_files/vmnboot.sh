#!/bin/bash
# start OvS
ovsdb-server --remote=punix:/usr/local/var/run/openvswitch/db.sock \
                  --remote=db:Open_vSwitch,Open_vSwitch,manager_options \
                  --private-key=db:Open_vSwitch,SSL,private_key \
                  --certificate=db:Open_vSwitch,SSL,certificate \
                  --bootstrap-ca-cert=db:Open_vSwitch,SSL,ca_cert \
                  --pidfile --detach
ovs-vsctl --no-wait init
ovs-vswitchd --pidfile --detach

ovs-ofctl add-flow br0 priority=1,ip,actions=mod_nw_src:11.11.11.11,output:controller
# send UDP packet for packet_in
ip r add 11.11.11.11 dev br0
arp -s 11.11.11.11 fa:16:3e:35:cc:2e
echo “help” > /dev/udp/11.11.11.11/58549

