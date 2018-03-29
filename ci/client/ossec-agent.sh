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

# Trap exit signals and do a proper shutdown
trap "ossec_shutdown; exit" SIGINT SIGTERM

fix_access_to_random

# Start services
/var/ossec/bin/agent-auth -m OssecServ
sleep 10
/etc/init.d/ossec start

# Return startup events to console
tail -f /var/ossec/logs/ossec.log