#!/bin/bash

#
# Initialize the custom data directory layout
#
source /data_dirs.env

cd /var/ossec
for ossecdir in "${DATA_DIRS[@]}"; do
  mv ${ossecdir} ${ossecdir}-template
  ln -s $(realpath --relative-to=$(dirname ${ossecdir}) data)/${ossecdir} ${ossecdir}
  if [ -d ${ossecdir} ] && [ "$(ls -A ${ossecdir}})" ]; then
    cp -r ${ossecdir}-template ${ossecdir}
  fi
done