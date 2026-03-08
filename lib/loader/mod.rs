//! Loading executable binaries into Falcon.
//!
//! ```
//! # use falcon::Error;
//! use falcon::loader::Elf;
//! use falcon::loader::Loader;
//! use std::path::Path;
//!
//! # fn example () -> Result<(), Error> {
//! // Load an elf for analysis
//! let elf = Elf::from_file(Path::new("test_binaries/simple-0/simple-0"))?;
//! // Lift a program from the elf
//! let program = elf.program()?;
//! for function in program.functions() {
//!     println!("0x{:08x}: {}", function.address(), function.name());
//! }
//! # Ok(())
//! # }
//! ```

use crate::architecture::Architecture;
use crate::executor::eval;
use crate::il;
use crate::memory;
use crate::translator::Options;
use crate::Error;
use std::any::Any;
use std::collections::{HashMap, HashSet};
use std::fmt;

mod elf;
mod json;
mod pe;
mod symbol;

pub use self::elf::*;
pub use self::json::*;
pub use self::pe::*;
pub use self::symbol::Symbol;

/// A declared entry point for a function.
#[derive(Clone, Debug, PartialEq)]
pub struct FunctionEntry {
    address: u64,
    name: Option<String>,
}

impl FunctionEntry {
    /// Create a new `FunctionEntry`.
    ///
    /// If no name is provided: `sup_{:X}` will be used to name the function.
    pub fn new(address: u64, name: Option<String>) -> FunctionEntry {
        FunctionEntry { address, name }
    }

    /// Get the address for this `FunctionEntry`.
    pub fn address(&self) -> u64 {
        self.address
    }

    /// Get the name for this `FunctionEntry`.
    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }
}

impl fmt::Display for FunctionEntry {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.name {
            Some(ref name) => write!(f, "FunctionEntry({} -> 0x{:X})", name, self.address),
            None => write!(f, "FunctionEntry(0x{:X})", self.address),
        }
    }
}

/// Generic trait for all loaders
pub trait Loader: fmt::Debug + Send + Sync {
    /// Get a model of the memory contained in the binary
    fn memory(&self) -> Result<memory::backing::Memory, Error>;

    /// Get addresses for known function entries
    fn function_entries(&self) -> Result<Vec<FunctionEntry>, Error>;

    /// The address program execution should begin at
    fn program_entry(&self) -> u64;

    /// Get the architecture of the binary
    fn architecture(&self) -> &dyn Architecture;

    /// Lift just one function from the executable
    fn function(&self, address: u64) -> Result<il::Function, Error> {
        self.function_extended(address, &Options::default())
    }

    /// Lift just one function from the executable, while also supplying
    /// translator options.
    fn function_extended(&self, address: u64, options: &Options) -> Result<il::Function, Error> {
        let translator = self.architecture().translator();
        let memory = self.memory()?;
        translator.translate_function_extended(&memory, address, options)
    }

    /// Cast loader to `Any`
    fn as_any(&self) -> &dyn Any;

    /// Get the symbols for this loader
    fn symbols(&self) -> Vec<Symbol>;

    /// Get the symbols as a hashmap by address
    fn symbols_map(&self) -> HashMap<u64, Symbol> {
        self.symbols()
            .into_iter()
            .map(|symbol| (symbol.address(), symbol))
            .collect()
    }

    /// Lift executable into an il::Program.
    ///
    /// Individual functions which fail to lift are omitted and ignored.
    fn program(&self) -> Result<il::Program, Error> {
        Ok(self.program_verbose(&Options::default())?.0)
    }

    /// Lift executable into an `il::Program`.
    ///
    /// Errors encountered while lifting specific functions are collected, and
    /// returned with the `FunctionEntry` identifying the function. Only
    /// catastrophic errors should cause this function call to fail.
    fn program_verbose(
        &self,
        options: &Options,
    ) -> std::result::Result<(il::Program, Vec<(FunctionEntry, Error)>), Error> {
        // Get out architecture-specific translator
        let translator = self.architecture().translator();

        // Create a mapping of the file memory
        let memory = self.memory()?;

        let mut program = il::Program::new();

        let mut translation_errors: Vec<(FunctionEntry, Error)> = Vec::new();

        for function_entry in self.function_entries()? {
            let address = function_entry.address();
            // Ensure this memory is marked executable
            if memory
                .permissions(address)
                .map_or(false, |p| p.contains(memory::MemoryPermissions::EXECUTE))
            {
                match translator.translate_function_extended(&memory, address, options) {
                    Ok(mut function) => {
                        function.set_name(function_entry.name().map(|n| n.to_string()));
                        program.add_function(function);
                    }
                    Err(e) => translation_errors.push((function_entry.clone(), e)),
                };
            }
        }

        Ok((program, translation_errors))
    }

    /// Lift executable into an `il::Program`, while recursively resolving branch
    /// targets into functions.
    ///
    /// program_recursive silently drops any functions that cause lifting
    /// errors. If you care about those, use `program_recursive_verbose`.
    fn program_recursive(&self) -> Result<il::Program, Error> {
        Ok(self.program_recursive_verbose(&Options::default())?.0)
    }

    /// Lift executable into an `il::Program`, while recursively resolving branch
    /// targets into functions.
    ///
    /// Works in a similar manner to `program_recursive`
    fn program_recursive_verbose(
        &self,
        options: &Options,
    ) -> std::result::Result<(il::Program, Vec<(FunctionEntry, Error)>), Error> {
        fn call_targets(function: &il::Function) -> Vec<u64> {
            let call_targets =
                function
                    .blocks()
                    .iter()
                    .fold(Vec::new(), |mut call_targets, block| {
                        block.instructions().iter().for_each(|instruction| {
                            if let il::Operation::Branch { ref target } = *instruction.operation() {
                                if let Ok(constant) = eval(target) {
                                    call_targets.push(constant.value_u64().unwrap())
                                }
                            }
                        });
                        call_targets
                    });
            call_targets
        }

        let (mut program, mut translation_errors) = self.program_verbose(options)?;
        let mut processed = HashSet::new();

        loop {
            // Get the address of every function currently in the program
            let function_addresses = program
                .functions()
                .into_iter()
                .map(|function| function.address())
                .collect::<Vec<u64>>();

            let addresses = {
                // For every function in the program which is not currentl a
                // member of our processed set
                let functions = program
                    .functions()
                    .into_iter()
                    .filter(|function| !processed.contains(&function.address()))
                    .collect::<Vec<&il::Function>>();

                // Insert this function into the processed set
                functions.iter().for_each(|function| {
                    processed.insert(function.address());
                });

                // Collect the call targets in all functions that have not yet
                // been processed, and filter them against the functions already
                // in program.
                let addresses = functions
                    .into_iter()
                    .fold(HashSet::new(), |mut targets, function| {
                        call_targets(function).into_iter().for_each(|target| {
                            targets.insert(target);
                        });
                        targets
                    })
                    .into_iter()
                    .filter(|address| !function_addresses.contains(address))
                    .collect::<Vec<u64>>();

                if addresses.is_empty() {
                    break;
                }

                addresses
            };

            // For each address, attempt to lift a function
            for address in addresses {
                match self.function_extended(address, options) {
                    Ok(function) => program.add_function(function),
                    Err(e) => {
                        let function_entry = FunctionEntry::new(address, None);
                        translation_errors.push((function_entry, e));
                    }
                }
            }
        }

        Ok((program, translation_errors))
    }
}
