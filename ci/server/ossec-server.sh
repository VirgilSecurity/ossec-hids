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


# TODO: Remove it !
if [ ! -f ${DATA_PATH}/etc/sslmanager.key ]; then
	openssl genrsa -out ${DATA_PATH}/etc/sslmanager.key 4096
	openssl req -new -x509 -key ${DATA_PATH}/etc/sslmanager.key -out ${DATA_PATH}/etc/sslmanager.cert -days 3650 -subj /CN=${HOSTNAME}/
fi

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
	pushd "${DATA_PATH}"
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
mkdir /var/ossec/queue

# Own by ossec
tree -fai /var/ossec | xargs -L1 -I{} chown ossec:ossec {}

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
  /var/ossec/bin/ossec-authd -N -d -d -d -p 1516 $AUTHD_OPTIONS &
  AUTHD_PID=$!
fi
sleep 15 # give ossec a reasonable amount of time to start before checking status
LAST_OK_DATE=`date +%s`

# Add a dummy agent so remoted can start
# if [ ! -s /var/ossec/etc/client.keys ] ; then
# 	/var/ossec/bin/manage_agents -f /var/ossec/default_agent
# fi

# Start OSSEC services
/var/ossec/bin/ossec-control start

# Return startup events to console
tail -f /var/ossec/logs/ossec.log