#!/bin/bash

source ~/.profile && \
cd /falcon && \
cargo test && \
cargo test -- --ignored && \
cargo test --features thread_safe&& \
cargo install cargo-tarpaulin && \
cargo tarpaulin -i --ignore-tests --no-count --ciserver travis-ci --coveralls $1