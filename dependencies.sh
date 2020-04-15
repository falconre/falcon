#!/bin/sh
if [ `whoami` != "root" ]; then
	echo "$0 must be run as root"
	exit 1
fi

grep 'ID=debian' /etc/os-release
if [ $? -eq 0 ]; then
	# Commands that are common to all Debian distros
	export DEBIAN_FRONTEND=noninteractive
	apt-get update
	apt-get -y dist-upgrade
	apt-get -y install curl gnupg2 apt-transport-https

	# Release-specific commands
	codename=`grep 'VERSION_CODENAME=' /etc/os-release | sed 's/.*=//g'`
	if [ "$codename" = "stretch" ]; then
		echo "deb http://apt.llvm.org/stretch/ llvm-toolchain-stretch-4.0 main" | tee -a /etc/apt/sources.list
		echo "deb-src http://apt.llvm.org/stretch/ llvm-toolchain-stretch-4.0 main" | tee -a /etc/apt/sources.list
		curl http://apt.llvm.org/llvm-snapshot.gpg.key | apt-key add -
		apt-get update
		apt-get -y install build-essential clang-4.0 curl llvm-4.0-dev \
			libcapstone3 libcapstone-dev libclang-4.0-dev pkg-config
	elif [ "$codename" = "buster" ]; then
		apt-get -y install build-essential clang curl llvm-dev \
			libcapstone3 libcapstone-dev libclang-dev pkg-config
	else
		echo "Unsupported version of Debian"
		exit 1
	fi
	apt-get clean
else
	echo "Unsupported Distro"
	exit 1
fi

