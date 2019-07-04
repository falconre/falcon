#!/bin/bash

source ~/.profile && \
cd /falcon && \
cargo test && \
cargo test -- --ignored && \
cargo test --features thread_safe