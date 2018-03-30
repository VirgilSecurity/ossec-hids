#!/bin/bash

#
# OSSEC container bootstrap. See the README for information of the environment
# variables expected by this script.
#

function ossec_shutdown(){
  /var/ossec/bin/ossec-control stop;
}

function fix_access_to_random() {
	pushd "${DATA_PATH}"
		if [ ! -d "dev" ]; then
			mkdir "dev"
			mount -o bind /dev dev/
		fi 
	popd
}

echo "AGENT >>> 1"

# Trap exit signals and do a proper shutdown
trap "ossec_shutdown; exit" SIGINT SIGTERM

echo "AGENT >>> 2"

fix_access_to_random

echo "AGENT >>> 3"

# Start services
/var/ossec/bin/agent-auth -N -d -d -d -p 1516 -m OssecServ

echo "AGENT >>> 4"

sleep 10

echo "AGENT >>> 5" 

/var/ossec/bin/ossec-control start

echo "AGENT >>> 6"

# Return startup events to console
tail -f /var/ossec/logs/ossec.log

echo "AGENT >>> 7"