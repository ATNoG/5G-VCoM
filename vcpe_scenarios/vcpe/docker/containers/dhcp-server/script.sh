#!/bin/sh

LOG_DIRECTORY='/sys/class/net/eth0/operstate'

while true
do

if [ -e "$LOG_DIRECTORY" ] 
then
	/usr/sbin/dhcpd -4 -f -d --no-pid -cf /etc/dhcp/dhcpd.conf
	#exit 0
fi

sleep 0.5

done



