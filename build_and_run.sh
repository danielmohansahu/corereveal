#!/usr/bin/bash

set -eo pipefail

# get path to here
SCRIPTPATH="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"

# build and tag docker image
IMAGE=ghidra-development:latest
docker build -t $IMAGE $SCRIPTPATH/

# drop into a container
rocker --x11 --volume $SCRIPTPATH/ghidra-project/.ghidra:/root/.ghidra --volume $SCRIPTPATH:/root/workspace -- $IMAGE byobu
