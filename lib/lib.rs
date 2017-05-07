#![allow(dead_code, unused_variables)]

#[macro_use] extern crate bitflags;
extern crate capstone_rust;
#[macro_use] extern crate error_chain;
extern crate goblin;
extern crate ketos;
#[macro_use] extern crate ketos_derive;
#[macro_use] extern crate log;


pub mod analysis;
pub mod executor;
pub mod graph;
pub mod il;
pub mod loader;
pub mod translator;


pub mod error {
    error_chain! {
        types {
            Error, ErrorKind, ResultExt, Result;
        }

        foreign_links {
            Goblin(::goblin::error::Error);
            Io(::std::io::Error);
        }

        errors {
            Sort
            Arithmetic
        }
    }
}

pub use error::*;