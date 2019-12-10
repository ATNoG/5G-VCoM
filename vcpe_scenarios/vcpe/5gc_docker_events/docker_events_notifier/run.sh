#!/bin/bash

LOG_DIRECTORY='/var/log/5gc-docker-swarm/docker-events/notifier'
CONSUMERS_FILE='/opt/swarmc/5gc_docker_swarm/docker_events_notifier/notifier.yaml'

if [ ! -d "$LOG_DIRECTORY" ]; then
        mkdir -p $LOG_DIRECTORY
        touch $LOG_DIRECTORY/events.log
fi

/usr/bin/python /opt/swarmc/5gc_docker_swarm/docker_events_notifier/de_notifier/notifier.py $CONSUMERS_FILE >> $LOG_DIRECTORY/events.log 2>&1