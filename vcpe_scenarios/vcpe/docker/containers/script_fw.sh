
#!/bin/sh

LOG_DIRECTORY='/proc/sys/net/ipv4/conf/eth1'

while true
do

if [ -e "$LOG_DIRECTORY" ] 
then
	sh iprules
	exit 0
fi

sleep 0.5

done

