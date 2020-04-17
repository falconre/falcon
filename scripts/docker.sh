#!/bin/sh
# This will get all the dependencies for docker, install the community edition
# of docker, build the docker image, run it in the background and inform the
# user how they can connect to it.
#
# Usage: $0 [DOCKERFILE]
#
# DOCKERFILE = The Dockerfile to use (default: Dockerfile.stretch)
#

DOCKERFILE=Dockerfile.stretch
if [ ! -z "$1" ]; then
	DOCKERFILE="$1"
fi

# Install docker's dependencies and then docker itself
grep ID=debian /etc/os-release
if [ $? -eq 0 ]; then
	sudo DEBIAN_FRONTEND=noninteractive apt-get update -y
	sudo DEBIAN_FRONTEND=noninteractive apt-get install -y apt-transport-https ca-certificates curl software-properties-common gnupg2
	curl -fsSL https://download.docker.com/linux/debian/gpg | sudo apt-key add -
	sudo add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/debian $(lsb_release -cs) stable"
	sudo DEBIAN_FRONTEND=noninteractive apt-get update -y
	sudo DEBIAN_FRONTEND=noninteractive apt-get install -y docker-ce
else
	echo "Unsupported Distro"
	exit 1
fi

# Build the image
curl https://apt.llvm.org/llvm-snapshot.gpg.key > llvm-snapshot.gpg.key
sudo docker build -f "$DOCKERFILE" .
IMAGE_NAME=`sudo docker images | head -n 2 | tail -n 1 | tr -s ' ' | cut -d ' ' -f 3`
if [ "$IMAGE_NAME" = "" ]; then
	echo "Unable to build docker image"
	exit 1
fi

# Run the image
sudo docker run -dt $IMAGE_NAME
CONTAINER_NAME=`sudo docker ps | head -n 2 | tail -n 1 | cut -d ' ' -f 1`
if [ "$IMAGE_NAME" = "" ]; then
	echo "Unable to run docker container"
	exit 1
fi

# Tell the user how they can connect to the container
echo "Container running.  To connect to the container, run: "
echo sudo docker exec -it $CONTAINER_NAME /bin/bash

