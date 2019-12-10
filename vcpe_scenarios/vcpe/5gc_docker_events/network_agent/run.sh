#!/bin/bash

LOG_DIRECTORY='/var/log/5gc-docker-swarm/network-agent/'
CONFIG_FILE='/opt/swarmc/5gc_docker_swarm/network_agent/config.ini'

if [ ! -d "$LOG_DIRECTORY" ]; then
        mkdir -p $LOG_DIRECTORY
        touch $LOG_DIRECTORY/events.log
fi

/usr/bin/python /opt/swarmc/5gc_docker_swarm/network_agent/agent/agent.py $CONFIG_FILE >> $LOG_DIRECTORY/events.log 2>&1