#!/bin/bash

#
# OSSEC container bootstrap. See the README for information of the environment
# variables expected by this script.
#

BASE_PATH=/var/ossec

function ossec_shutdown(){
  /var/ossec/bin/ossec-control stop;
}

function fix_access_to_random() {
	pushd "${BASE_PATH}"
		if [ ! -d "dev" ]; then
			mkdir "dev"
			cd "dev"
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

export OSSEC_SERVER_IP=$(nslookup ossec-server | grep Address | sed -n 2p | awk '{$1=""; print $0}')

echo "OSSEC_SERVER_IP=${OSSEC_SERVER_IP}"
ping -c 3 ossec-server

sleep 5

# Start services
echo f9b1290fd2d23b8b8e6ba9793b1faf18 > /var/ossec/etc/authd.pass
/var/ossec/bin/agent-auth -N -d -d -d -p 1516 -m $OSSEC_SERVER_IP -P /var/ossec/etc/authd.pass
sleep 10
/var/ossec/bin/ossec-control start

# Return startup events to console
tail -f /var/ossec/logs/ossec.log

/bin/bash