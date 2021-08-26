#![recursion_limit = "128"]

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

#[macro_use]
extern crate error_chain;
#[macro_use]
extern crate serde_derive;

pub mod analysis;
pub mod architecture;
pub mod executor;
pub mod graph;
pub mod il;
pub mod loader;
pub mod memory;
pub mod transformation;
pub mod translator;

#[cfg(not(feature = "thread_safe"))]
use std::rc::Rc;
#[allow(clippy::upper_case_acronyms)]
#[cfg(not(feature = "thread_safe"))]
pub type RC<T> = Rc<T>;

#[cfg(feature = "thread_safe")]
use std::sync::Arc;
#[cfg(feature = "thread_safe")]
pub type RC<T> = Arc<T>;

/// Falcon Error types.
pub mod error {
    error_chain! {
        types {
            Error, ErrorKind, ResultExt, Result;
        }

        foreign_links {
            Bad64(::bad64::DecodeError);
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
            Analysis(m: String) {
                description("An error in the analysis")
                display("Analysis error: {}", m)
            }
            Arithmetic(m: String) {
                description("Error in evaluation of arithmetic expression")
                display("Arithmetic expression evaluation error: {}", m)
            }
            AccessUnmappedMemory(address: u64) {
                description("Attempt to access unmapped memory")
                display("Attempt to access unmapped memory at address 0x{:x}", address)
            }
            CapstoneError {
                description("Capstone failed")
                display("Capstone failed")
            }
            DisassemblyFailure {
                description("Unrecoverable error during disassembly")
                display("Disassembly Failure")
            }
            DivideByZero {
                description("Division by zero")
                display("Division by zero")
            }
            ExecutorScalar(name: String) {
                description("Executor can only execute over constant values")
                display("A scalar \"{}\" was found while executor was evaluating expression", name)
            }
            FunctionLocationApplication {
                description("Failed to apply il::FunctionLocation")
                display("Failed to apply il::FunctionLocation")
            }
            GraphEdgeNotFound(head: usize, tail: usize) {
                description("An edge was not found in a graph")
                display("The edge with head {} and tail {} does not exist in the graph", head, tail)
            }
            GraphVertexNotFound(vertex_id: usize) {
                description("A vertex was not found in a graph")
                display("The vertex id {} does not exist in the graph", vertex_id)
            }
            ProgramLocationMigration(reason: String) {
                description("Error migrating ProgramLocation between Program")
                display("Failed to migrate ProgramLocation between Program: {}", reason)
            }
            ProgramLocationApplication {
                description("Failed to apply il::ProgramLocation")
                display("Failed to apply il::ProgramLocation")
            }
            Sort {
                description("Sort error, invalid bitness between expressions")
                display("Sort error, invalid bitness between expressions")
            }
            TooManyAddressBits {
                description("A constant with >64 bits was used as an address")
                display("A constant with >64 bits was used as an address")
            }
            UnhandledIntrinsic(intrinsic_str: String) {
                description("An unhandled intrinsic was encountered during evaluation")
                display("Encountered unhandled intrinsic {}", intrinsic_str)
            }
        }
    }
}

pub use error::*;
