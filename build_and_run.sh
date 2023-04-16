#!/usr/bin/bash

set -eo pipefail

# get path to here
SCRIPTPATH="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"

# build and tag docker image
IMAGE=ghidra-development:latest
docker build -t $IMAGE $SCRIPTPATH/

# drop into a container
rocker --x11 --volume $SCRIPTPATH:/workspace -- $IMAGE byobu
