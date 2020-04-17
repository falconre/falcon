#!/bin/sh
# This will install the latest version of Rust.  If you want it to be
# installed for a nomrmal user, don't run this as root!
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs > rustup.sh
chmod +x rustup.sh
./rustup.sh -y
