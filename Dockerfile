FROM ubuntu:xenial

RUN apt-get update && \
    apt-get -y dist-upgrade && \
    apt-get -y install wget && \
    echo "deb http://apt.llvm.org/xenial/ llvm-toolchain-xenial-3.9 main" >> /etc/apt/sources.list && \
    echo "deb-src http://apt.llvm.org/xenial/ llvm-toolchain-xenial-3.9 main" >> /etc/apt/sources.list && \
    wget -O - http://apt.llvm.org/llvm-snapshot.gpg.key | apt-key add - && \
    apt-get update && \
    apt-get -y install build-essential \
                       clang-3.9 \
                       curl \
                       llvm-3.9-dev \
                       libcapstone3 \
                       libcapstone-dev \
                       libclang-3.9-dev \
                       pkg-config && \
    apt-get clean

RUN curl https://sh.rustup.rs -sSf > /tmp/install.sh && \
    chmod 755 /tmp/install.sh && \
    /tmp/install.sh -y

SHELL ["/bin/bash", "-c"]

COPY . /falcon/