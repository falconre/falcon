#!/bin/sh
# Script assumes the ability to run sudo without a password

grep 'ID=debian' /etc/os-release
if [ $? -eq 0 ]; then
	grep 'VERSION_CODENAME=stretch' /etc/os-release
	if [ $? -eq 0 ]; then
		sudo DEBIAN_FRONTEND=noninteractive apt-get update
		sudo DEBIAN_FRONTEND=noninteractive apt-get -y dist-upgrade
		sudo DEBIAN_FRONTEND=noninteractive apt-get -y install curl gnupg2 apt-transport-https
		echo "deb http://apt.llvm.org/stretch/ llvm-toolchain-stretch-4.0 main" | sudo tee -a /etc/apt/sources.list
		echo "deb-src http://apt.llvm.org/stretch/ llvm-toolchain-stretch-4.0 main" | sudo tee -a /etc/apt/sources.list
		curl http://apt.llvm.org/llvm-snapshot.gpg.key | sudo apt-key add -
		sudo DEBIAN_FRONTEND=noninteractive apt-get update
		sudo DEBIAN_FRONTEND=noninteractive apt-get -y install build-essential clang-4.0 curl llvm-4.0-dev \
			libcapstone3 libcapstone-dev libclang-4.0-dev pkg-config
		sudo DEBIAN_FRONTEND=noninteractive apt-get clean
		curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs > rustup.sh
		#curl https://sh.rustup.rs -sSf > /tmp/install.sh
		chmod +x rustup.sh
		./rustup.sh -y
	else
		echo "Unsupported version of Debian"
		exit 1
	fi
else
	echo "Unsupported Distro"
	exit 1
fi

