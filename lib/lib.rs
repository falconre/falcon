#![recursion_limit="128"]

//! Falcon: A Binary Analysis Framework in Rust.
//! 
//! Falcon is a framework in rust for implementing formal analyses over binary
//! programs. A quick synopsis of Falcon's modules:
//! 
//! * **analysis** - A fixed-point engine and methods for abstract interpretation
//! over Falcon IL. Example, usable analyses are given.
//! * **architecture** - Information on Falcon's supported architectures.
//! * **executor** - A concrete execution engine over Falcon IL.
//! * **graph** - A simple directed graph library.
//! * **il** - Falcon's Intermediate Language.
//! * **loader** - Loaders for binary formats, currently supporting Elf.
//! * **memory** - A layered memory model over generic types.
//! * **translator** - Translators from native architectures to Falcon IL.
//!
//! Falcon also has bindings for the scripting language
//! [gluon](https://github.com/gluon-lang/gluon), which makes exploratory 
//! analysis over Falcon quick and pleasant.
//!
//! ```
//! # use falcon::error::*;
//! use falcon::loader::Elf;
//! use falcon::loader::Loader;
//! use std::path::Path;
//!
//! # fn example () -> Result<()> {
//! let elf = Elf::from_file(Path::new("test_binaries/simple-0/simple-0"))?;
//! for function in elf.program()?.functions() {
//!     for block in function.blocks() {
//!         println!("Block {} in Function {:x}", block.index(), function.address());
//!         println!("{}", block);
//!     }
//! }
//! # Ok(())
//! # }
//! ```


extern crate base64;
#[macro_use]
extern crate bitflags;
extern crate byteorder;
#[macro_use]
extern crate error_chain;
extern crate falcon_capstone;
extern crate goblin;
#[macro_use]
extern crate log;
extern crate num_bigint;
extern crate num_traits;
extern crate serde;
#[macro_use]
extern crate serde_derive;
extern crate serde_json;


pub mod analysis;
pub mod architecture;
pub mod executor;
pub mod graph;
pub mod il;
pub mod loader;
pub mod memory;
pub mod translator;



#[cfg(not(feature = "thread_safe"))]
use std::rc::Rc;
#[cfg(not(feature = "thread_safe"))]
type RC<T> = Rc<T>;

#[cfg(feature = "thread_safe")]
use std::sync::Arc;
#[cfg(feature = "thread_safe")]
type RC<T> = Arc<T>;


/// Falcon Error types.
pub mod error {
    error_chain! {
        types {
            Error, ErrorKind, ResultExt, Result;
        }

        foreign_links {
            Base64(::base64::DecodeError);
            Capstone(::falcon_capstone::capstone::CsErr);
            Goblin(::goblin::error::Error);
            Io(::std::io::Error);
            Json(::serde_json::Error);
            ParseBigIntError(::num_bigint::ParseBigIntError);
            ParseIntError(::std::num::ParseIntError);
            Utf8(::std::string::FromUtf8Error);
        }

        errors {
            Arithmetic(m: String) {
                description("Error in evaluation of arithmetic expression")
                display("Arithmetic expression evaluation error: {}", m)
            }
            AccessUnmappedMemory(address: u64) {
                description("Attempt to access unmapped memory")
                display("Attempt to access unmapped memory at address 0x{:x}", address)
            }
            ExecutorScalar(name: String) {
                description("Executor can only execute over constant values")
                display("A scalar \"{}\" was found while executor was evaluating expression", name)
            }
            ProgramLocationMigration(reason: String) {
                description("Error migrating ProgramLocation between Program")
                display("Failed to migrate ProgramLocation between Program: {}", reason)
            }
            Sort {
                description("Sort error, invalid bitness between expressions")
                display("Sort error, invalid bitness between expressions")
            }
            TooManyAddressBits {
                description("A constant with >64 bits was used as an address")
                display("A constant with >64 bits was used as an address")
            }
        }
    }
}

pub use error::*;