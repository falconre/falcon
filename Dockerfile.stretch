FROM debian:stretch 
 
RUN apt-get update && \ 
    apt-get -y dist-upgrade && \ 
    apt-get -y install curl gnupg2 && \ 
    echo "deb http://apt.llvm.org/stretch/ llvm-toolchain-stretch-4.0 main" >> /etc/apt/sources.list && \ 
    echo "deb-src http://apt.llvm.org/stretch/ llvm-toolchain-stretch-4.0 main" >> /etc/apt/sources.list && \ 
    curl http://apt.llvm.org/llvm-snapshot.gpg.key | apt-key add - && \ 
    apt-get update && \ 
    apt-get -y install build-essential \ 
                       clang-4.0 \ 
                       curl \ 
                       llvm-4.0-dev \ 
                       libcapstone3 \ 
                       libcapstone-dev \ 
                       libclang-4.0-dev \ 
                       pkg-config && \ 
    apt-get clean 
 
RUN curl https://sh.rustup.rs -sSf > /tmp/install.sh && \ 
    chmod 755 /tmp/install.sh && \ 
    /tmp/install.sh -y 
 
SHELL ["/bin/bash", "-c"] 
 
COPY . /falcon/