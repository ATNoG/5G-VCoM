#!/bin/sh

sudo ovs-vsctl set-manager tcp:$1:6640 ptcp:6640
