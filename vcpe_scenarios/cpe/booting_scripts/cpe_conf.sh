#!/bin/sh

LOG_DIRECTORY='/usr/local/var/run/openvswitch/'

nw_dst=$1

flag=0

while flag=0
do

for entry in "$LOG_DIRECTORY"/*
do
	if [[ $entry == *"cpe"* ]]; then
		bridge=${entry##*/}
		bridge=${bridge%.*}
		sudo ip addr add 50.0.0.1/24 dev ${bridge}
		sudo ip link set ${bridge} up
		sudo ip r add ${nw_dst} via 50.0.0.1
		sudo ip r add 10.0.0.11 via 50.0.0.1
		sudo ifconfig wlan0 10.0.0.1 up
		sudo ifconfig gre0 up
		flag=1
		exit 0 
	fi
done

sleep 0.5

done
