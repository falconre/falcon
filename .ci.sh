#!/bin/bash

source ~/.profile && \
cd /falcon && \
cargo test && \
cargo test -- --ignored && \
curl -sL https://github.com/xd009642/tarpaulin/releases/download/0.5.0/cargo-tarpaulin-0.5.0-travis.tar.gz | tar xvz -C $HOME/.cargo/bin && \
cargo tarpaulin -i --ignore-tests --no-count --ciserver travis-ci --coveralls $1