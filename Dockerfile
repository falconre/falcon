FROM debian:buster

ARG TARGETPLATFORM
RUN echo "Building for $TARGETPLATFORM"

RUN apt-get update && \
    apt-get -y install \
        build-essential \
        clang \
        llvm \
        wget && \
    apt-get clean

RUN mkdir /opt/capstone && \
    cd /opt/capstone && \
    wget https://github.com/aquynh/capstone/archive/4.0.2.tar.gz && \
    tar xf 4.0.2.tar.gz && \
    cd capstone-4.0.2 && \
    make -j && \
    make install

ENV RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:$PATH

RUN set -eux; \
    if [ "$TARGETPLATFORM" = "linux/arm64" ]; then ARCHITECTURE=aarch64; else ARCHITECTURE=x86_64; fi && \
    url="https://static.rust-lang.org/rustup/dist/${ARCHITECTURE}-unknown-linux-gnu/rustup-init"; \
    wget "$url"; \
    chmod +x rustup-init; \
    ./rustup-init -y --no-modify-path; \
    rm rustup-init; \
    chmod -R a+w $RUSTUP_HOME $CARGO_HOME; \
    rustup --version; \
    cargo --version; \
    rustc --version;

SHELL ["/bin/bash", "-c"]

COPY . /falcon/
