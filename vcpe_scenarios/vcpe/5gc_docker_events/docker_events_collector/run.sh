#!/bin/bash

LOG_DIRECTORY='/var/log/docker-events/collector'
CONFIG_FILE='/opt/swarmc/5gc_docker_swarm/docker_events_collector/collector.yaml'

if [ ! -d "$LOG_DIRECTORY" ]; then
        mkdir -p $LOG_DIRECTORY
        touch $LOG_DIRECTORY/events.log
fi

/usr/local/bin/docker-events -c $CONFIG_FILE -m de_collector.collector >> $LOG_DIRECTORY/events.log 2>&1