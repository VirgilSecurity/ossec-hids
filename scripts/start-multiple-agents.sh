#!/bin/bash

SCRIPT_FOLDER="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
LAUNCH_SCRIPT="${SCRIPT_FOLDER}/start.applescript"

osascript "${LAUNCH_SCRIPT}"
