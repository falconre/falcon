//! Loading executable binaries into Falcon

pub mod elf;
pub mod json;
pub mod memory;

use error::*;
use il;
use std::fmt;
use translator::TranslationMemory;
use types::Architecture;


/// A declared entry point for a function.
#[derive(Clone, Debug, PartialEq)]
pub struct FunctionEntry {
    address: u64,
    name: Option<String>
}


impl FunctionEntry {
    /// Create a new `FunctionEntry`.
    ///
    /// If no name is provided: `sup_{:X}` will be used to name the function.
    pub fn new(address: u64, name: Option<String>) -> FunctionEntry {
        FunctionEntry {
            address: address,
            name: name
        }
    }

    /// Get the address for this `FunctionEntry`.
    pub fn address(&self) -> u64 {
        self.address
    }

    /// Get the name for this `FunctionEntry`.
    pub fn name(&self) -> &Option<String> {
        &self.name
    }
}


impl fmt::Display for FunctionEntry {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.name {
            Some(ref name) => write!(f, "{} -> {:X}", name, self.address),
            None => write!(f, "{:X}", self.address)
        }
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

    /// Lift just one function from the executable
    fn function(&self, address: u64) -> Result<il::Function> {
        let translator = self.architecture()?.translator();
        let memory = self.memory()?;
        Ok(translator.translate_function(&memory, address)?)
    }

    /// Lift executable into an il::Program
    fn program(&self) -> Result<il::Program> {
        // Get out architecture-specific translator
        let translator = self.architecture()?.translator();

        // Create a mapping of the file memory
        let memory = self.memory()?;

        let mut program = il::Program::new();

        for function_entry in self.function_entries()? {
            let address = function_entry.address();
            // Ensure we can actually get memory at this function address
            if TranslationMemory::get_u8(&memory, address).is_some() {
                let mut function = translator.translate_function(&memory, address)?;
                function.set_name(function_entry.name().clone());
                program.add_function(function);
            }
        }

        Ok(program)
    }
}