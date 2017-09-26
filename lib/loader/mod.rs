//! Loading executable binaries into Falcon

pub mod elf;
pub mod json;
pub mod memory;

use error::*;
use translator;
use il;
use std::fmt;
use types::Endian;

/// An enum of architectures supported by the loader.
#[derive(Clone, Debug)]
pub enum Architecture {
    X86
}


impl Architecture {
    /// Get the endiannes of an `Architecture`
    pub fn endian(&self) -> Endian {
        match *self {
            Architecture::X86 => Endian::Little
        }
    }
}


/// A declared entry point for a function.
#[derive(Clone, Debug, PartialEq)]
pub struct FunctionEntry {
    address: u64,
    name: String
}


impl FunctionEntry {
    /// Create a new `FunctionEntry`.
    ///
    /// If no name is provided: `sup_{:X}` will be used to name the function.
    pub fn new(address: u64, name: Option<String>) -> FunctionEntry {
        match name {
            Some(name) => FunctionEntry {
                address: address,
                name: name
            },
            None => {
                FunctionEntry {
                    address: address,
                    name: format!("sub_{:X}", address)
                }
            }
        }
    }

    /// Get the address for this `FunctionEntry`.
    pub fn address(&self) -> u64 {
        self.address
    }

    /// Get the name for this `FunctionEntry`.
    pub fn name(&self) -> &str {
        &self.name
    }
}


impl fmt::Display for FunctionEntry {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{} -> {:X}", self.name, self.address)
    }
}


/// Generic trait for all loaders
pub trait Loader: Clone {
    /// Get a model of the memory contained in the binary
    fn memory(&self) -> Result<memory::Memory>;

    /// Get addresses for known function entries
    fn function_entries(&self) -> Result<Vec<FunctionEntry>>;

    /// The address program execution should begin at
    fn program_entry(&self) -> u64;

    /// Get the architecture of the binary
    fn architecture(&self) -> Result<Architecture>;

    /// Get the translator for this binary's architecture
    fn translator(&self) -> Result<Box<translator::Arch>> {
        match self.architecture() {
            Ok(arch) => match arch {
                Architecture::X86 => Ok(Box::new(translator::x86::X86::new()))
            },
            Err(_) => bail!("Unsupported Architecture")
        }
    }

    /// Lift just one function from the executable
    fn function(&self, address: u64) -> Result<il::Function> {
        let translator = self.translator()?;
        let memory = self.memory()?;
        Ok(translator.translate_function(&memory, address)?)
    }

    /// Lift executable into an il::Program
    fn to_program(&self) -> Result<il::Program> {
        // Get out architecture-specific translator
        let translator = self.translator()?;

        // Create a mapping of the file memory
        let memory = self.memory()?;

        let mut program = il::Program::new();

        for function_entry in self.function_entries()? {
            let address = function_entry.address();
            trace!("adding function at {:X}", address);
            let mut function = translator.translate_function(&memory, address)?;
            function.set_name(Some(function_entry.name().to_string()));
            program.add_function(function);
        }

        Ok(program)
    }
}