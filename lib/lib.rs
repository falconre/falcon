//! Falcon: A Binary Analysis Framework in Rust.

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
pub mod platform;
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
            Sort {
                description("Sort error, invalid bitness between expressions")
                display("Sort error, invalid bitness between expressions")
            }
            Arithmetic(m: String) {
                description("Error in evaluation of arithmetic expression")
                display("Arithmetic expression evaluation error: {}", m)
            }
            AccessUnmappedMemory(address: u64) {
                description("Attempt to access unmapped memory")
                display("Attempt to access unmapped memory at address 0x{:x}", address)
            }
        }
    }
}

pub use error::*;