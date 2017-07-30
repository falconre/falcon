#![allow(dead_code, unused_variables)]

extern crate base64;
#[macro_use]
extern crate bitflags;
extern crate capstone_rust;
extern crate core;
#[macro_use]
extern crate error_chain;
extern crate goblin;
#[macro_use]
extern crate log;
extern crate regex;
extern crate serde;
#[macro_use]
extern crate serde_derive;
extern crate serde_json;


pub mod analysis;
pub mod engine;
pub mod executor;
pub mod graph;
pub mod il;
pub mod loader;
mod tests;
pub mod translator;


pub mod error {
    error_chain! {
        types {
            Error, ErrorKind, ResultExt, Result;
        }

        foreign_links {
            Base64(::base64::DecodeError);
            Goblin(::goblin::error::Error);
            Io(::std::io::Error);
            Json(::serde_json::Error);
            ParseIntError(::core::num::ParseIntError);
            Regex(::regex::Error);
            Utf8(::std::string::FromUtf8Error);
        }

        errors {
            Sort
            Arithmetic
        }
    }
}

pub use error::*;