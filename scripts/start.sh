#!/bin/bash

SCRIPT_FOLDER="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
LAUNCH_SCRIPT="${SCRIPT_FOLDER}/start.scpt"

if [ $# -le 1 ]; then
    if [ $# -ne 0 ]; then
        case $1 in
            "signle")
                osascript "${SCRIPT_FOLDER}/start_single.scpt"
                ;;
            "full")
                osascript "${SCRIPT_FOLDER}/start.scpt"
                ;;
            *)
                echo "illegal argument"
                ;;
        esac
    else
        osascript "${SCRIPT_FOLDER}/start.scpt"
    fi
else
    echo "illegal number of parameters"
fi