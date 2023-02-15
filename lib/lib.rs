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
//! # use falcon::Error;
//! use falcon::loader::Elf;
//! use falcon::loader::Loader;
//! use std::path::Path;
//!
//! # fn example () -> Result<(), Error> {
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

use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("An error in the analysis: `{0}`")]
    Analysis(String),
    #[error("Error in evaluation of arithmetic expression: `{0}`")]
    Arithmetic(String),
    #[error("Attempt to access unmapped memory at address 0x`{0:x}`")]
    AccessUnmappedMemory(u64),
    #[error("Bad64: `{0}`")]
    Bad64(#[from] bad64::DecodeError),
    #[error("Base64: `{0}`")]
    Base64(#[from] base64::DecodeError),
    #[error("FalconCapstone: `{0}`")]
    Capstone(#[from] falcon_capstone::capstone::CsErr),
    #[error("Capstone failed")]
    CapstoneError,
    #[error("`{0}` - `{1}`")]
    Chain(Box<Error>, Box<Error>),
    #[error("ControlFlowGraph successor not found")]
    ControlFlowGraphSuccessorNotFound,
    #[error("ControlFlowGraph entry and/or exit nodes not found")]
    ControlFlowGraphEntryExitNotFound,
    #[error("Custom: `{0}`")]
    Custom(String),
    #[error("Unrecoverable error during disassembly")]
    DisassemblyFailure,
    #[error("Division by zero")]
    DivideByZero,
    #[error("Elf Linker: relocations unsuppored")]
    ElfLinkerRelocationsUnsupported,
    #[error("Executor received an invalid address")]
    ExecutorInvalidAddress,
    #[error("Executor failed to lift function at `{0}` `{1}`")]
    ExecutorLiftFail(u64, Box<Error>),
    #[error("Executor can only execute over constant values, encountered `{0}`")]
    ExecutorScalar(String),
    #[error("Executor did not have a valid location")]
    ExecutorNoValidLocation,
    #[error("Executor failed to get edge consition")]
    ExecutorNoEdgeCondition,
    #[error("Falcon internal error: {0}")]
    FalconInternal(String),
    #[error("Max steps reached while conducting fixed-point analysis")]
    FixedPointMaxSteps,
    #[error("Found a state which was not >= previous state (it was `{0:?}`) @ `{1}`")]
    FixedPointOrdering(String, il::ProgramLocation),
    #[error("FixedPoint requires an entry point in CFG")]
    FixedPointRequiresEntry,
    #[error("Failed to apply il::FunctionLocation")]
    FunctionLocationApplication,
    #[error("Goblin: `{0}`")]
    Goblin(#[from] goblin::error::Error),
    #[error("The edge with head `{0}` and tail `{1}` does not exist in the graph")]
    GraphEdgeNotFound(usize, usize),
    #[error("The vertex id `{0}` does not exist in the graph")]
    GraphVertexNotFound(usize),
    #[error("Invalid File Format: `{0}`")]
    InvalidFileFormat(String),
    #[error("Io: `{0}`")]
    Io(#[from] std::io::Error),
    #[error("Json: `{0}`")]
    Json(#[from] serde_json::Error),
    #[error("BigInt: `{0}`")]
    ParseBigIntError(#[from] num_bigint::ParseBigIntError),
    #[error("Failed to apply il::ProgramLocation")]
    ProgramLocationApplication,
    #[error("Sort error, invalid bitness between expressions")]
    Sort,
    #[error("A constant with >64 bytes was used as an address")]
    TooManyAddressBits,
    #[error("An unhandled intrinsic was encountered during evaluation")]
    UnhandledIntrinsic(String),
    #[error("Unsupported Architecture")]
    UnsupprotedArchitecture,
    #[error("Utf8: `{0}`")]
    Utf8(#[from] std::string::FromUtf8Error),
}

impl From<&str> for Error {
    fn from(s: &str) -> Error {
        Error::Custom(s.to_string())
    }
}

impl From<String> for Error {
    fn from(s: String) -> Error {
        Error::Custom(s)
    }
}

impl Error {
    pub fn chain(self, other: Error) -> Error {
        Error::Chain(Box::new(self), Box::new(other))
    }
}
