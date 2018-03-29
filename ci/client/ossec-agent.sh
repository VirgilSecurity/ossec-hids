#!/bin/bash

#
# OSSEC container bootstrap. See the README for information of the environment
# variables expected by this script.
#

function ossec_shutdown(){
  /var/ossec/bin/ossec-control stop;
}

# Trap exit signals and do a proper shutdown
trap "ossec_shutdown; exit" SIGINT SIGTERM

# Start services
/var/ossec/bin/agent-auth -m OssecServ
sleep 10
/etc/init.d/ossec start

# Return startup events to console
tail -f /var/ossec/logs/ossec.log