#!/bin/bash

source ~/.profile
cd /falcon
cargo test
apt-get install -y cmake libssl-dev
cargo install cargo-tarpaulin
cargo tarpaulin --ciserver travis-ci --coveralls $1