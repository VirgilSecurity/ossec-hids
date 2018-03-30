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
			ln -s /dev/urandom ./
			ln -s /dev/random ./
			ln -s /dev/zero ./
		fi 
	popd
}

# Trap exit signals and do a proper shutdown
trap "ossec_shutdown; exit" SIGINT SIGTERM

# Create required directories
mkdir /var/ossec/var
mkdir /var/ossec/var/run
mkdir /var/ossec/queue

# Own by ossec
tree -fai /var/ossec | xargs -L1 -I{} chown ossec:ossec {}

fix_access_to_random

# Start services
/var/ossec/bin/agent-auth -N -d -d -d -p 1516 -m OssecServ
sleep 10
/var/ossec/bin/ossec-control start

# Return startup events to console
tail -f /var/ossec/logs/ossec.log