#!/bin/bash

cd /falcon && \
cargo test && \
cargo test -- --ignored && \
cargo test --features thread_safe && \
cargo clippy --all