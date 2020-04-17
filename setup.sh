#!/bin/sh
sudo ./dependencies.sh
if [ $? -ne 0 ]; then
	echo "Failed to install dependencies"
	exit 1
fi
./get_rust.sh
if [ $? -ne 0 ]; then
	echo "Failed to install rust"
	exit 1
fi

. $HOME/.cargo/env
git clone https://github.com/falconre/falcon
cd falcon
cargo build
cargo new falcontest
cd falcontest
echo 'falcon = { path = ".." }' >> Cargo.toml
echo 'extern crate falcon;

use falcon::loader::Elf;
use falcon::loader::Loader;
use std::path::Path;

fn main() {
    let elf = Elf::from_file(Path::new("/bin/sh")).unwrap();
    for function in elf.program().unwrap().functions() {
        for block in function.blocks() {
            let f = elf.program().unwrap().function_by_address(function.address()).unwrap().name();
            println!("Block {} in Function {:x} ({})", block.index(), function.address(), f);
            println!("{}", block);
        }
    }
}' > src/main.rs
cargo build
cargo run

exit $?
