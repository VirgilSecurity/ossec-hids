#!/bin/bash

#
# OSSEC container bootstrap. See the README for information of the environment
# variables expected by this script.
#
FIRST_TIME_INSTALLATION=false
BASE_PATH=/var/ossec
DATA_PATH=/var/ossec/data

DATA_DIRS="etc rules logs stats queue"
for ossecdir in $DATA_DIRS; do
	if [ ! -e "${DATA_PATH}/${ossecdir}" ]; then
    		echo "Installing ${ossecdir}"
		mkdir -p ${DATA_PATH}/${ossecdir}
    		cp -a /var/ossec/${ossecdir}-template/* ${DATA_PATH}/${ossecdir}/ 2>/dev/null
    		FIRST_TIME_INSTALLATION=true
  	fi
done

#
# Check for the process_list file. If this file is missing, it doesn't
# count as a first time installation
#
touch ${DATA_PATH}/process_list
chgrp ossec ${DATA_PATH}/process_list
chmod g+rw ${DATA_PATH}/process_list

#
# If this is a first time installation, then do the  
# special configuration steps.
#
AUTO_ENROLLMENT_ENABLED=${AUTO_ENROLLMENT_ENABLED:-true}

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

function ossec_shutdown(){
  /var/ossec/bin/ossec-control stop;
  if [ $AUTO_ENROLLMENT_ENABLED == true ]
  then
     kill $AUTHD_PID
  fi
}

# Trap exit signals and do a proper shutdown
trap "ossec_shutdown; exit" SIGINT SIGTERM

# Create required directories
mkdir /var/ossec/var
mkdir /var/ossec/var/run
mkdir /var/ossec/var/log
mkdir /var/ossec/queue
mkdir /var/ossec/queue/fts
mkdir /var/ossec/queue/ossec
mkdir /var/ossec/queue/rids
mkdir /var/ossec/queue/agent-info
mkdir -p /var/ossec/queue/alerts
mkdir -p /var/ossec/logs/archives
mkdir -p /var/ossec/logs/alerts
mkdir -p /var/ossec/logs/firewall
mkdir -p /var/ossec/queue/syscheck


# Own by ossec
tree -fai /var/ossec | xargs -L1 -I{} chown ossec:ossec {} 2>/dev/null

chmod -R g+rwx /var/ossec/var
chmod -R g+rwx /var/ossec/var/run/
chmod -R g+rwx /var/ossec/var/log
chmod -R g+rwx /var/ossec/queue/  
chmod -R g+rwx /var/ossec/queue/alerts/
chmod -R g+rwx /var/ossec/queue/alerts/execq 
chmod -R g+rwx /var/ossec/logs/archives
chmod -R g+rwx /var/ossec/logs/alerts
chmod -R g+rwx /var/ossec/logs/firewall
chmod -R g+rwx /var/ossec/queue/rids
chmod -R g+rwx /var/ossec/queue/alerts
chmod -R g+rwx /var/ossec/queue/syscheck
chmod -R g+rwx mkdir /var/ossec/queue/agent-info

fix_access_to_random

#
# Startup the services
#

# Start Postfix
/usr/sbin/postfix start

# Start VirgilD
/opt/virgild -mode=local -db=sqlite3:/var/ossec/data/virgild.db &

# Allow agents registration ???
chmod -R g+rw ${DATA_PATH}/logs/ ${DATA_PATH}/stats/ ${DATA_PATH}/queue/ 

if [ $AUTO_ENROLLMENT_ENABLED == true ]; then
  echo "Starting ossec-authd..."
  echo f9b1290fd2d23b8b8e6ba9793b1faf18 > /var/ossec/etc/authd.pass
  /var/ossec/bin/ossec-authd -N -d -d -d -p 1515 $AUTHD_OPTIONS &
  AUTHD_PID=$!
fi
sleep 30 # give ossec a reasonable amount of time to start before checking status
LAST_OK_DATE=`date +%s`

# Start OSSEC services
/var/ossec/bin/ossec-control start

# Return startup events to console
tail -f /var/ossec/logs/ossec.log