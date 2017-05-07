//! Loading executable binaries into Falcon

pub mod elf;
pub mod memory;

use error::*;
use translator;
use translator::Arch;
use il;
use std::collections::BTreeMap;
use std::fmt;

pub enum Architecture {
    X86
}


#[derive(Clone, Debug, ForeignValue, IntoValue, PartialEq)]
pub struct FunctionEntry {
    address: u64,
    name: String
}


impl FunctionEntry {
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

    pub fn address(&self) -> u64 {
        self.address
    }

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
pub trait Loader {
    /// Get a model of the memory contained in the binary
    fn memory(&self) -> Result<memory::Memory>;

    /// Get addresses for known function entries
    fn function_entries(&self) -> Result<Vec<FunctionEntry>>;

    /// Get the architecture of the binary
    fn architecture(&self) -> Result<Architecture>;

    /// Turn this into an il::Program
    fn to_program(&self) -> Result<il::Program> {
        let translator = match self.architecture() {
            Ok(arch) => match arch {
                Architecture::X86 => translator::x86::X86::new()
            },
            Err(_) => bail!("Unsupported Architecture")
        };

        let memory = self.memory()?;
        let mut functions = BTreeMap::new();
        for function_entry in self.function_entries()? {
            info!("Translating function {}", function_entry.name());
            let address = function_entry.address();
            let mut function = translator.translate_function(&memory, address)?;
            function.set_name(Some(function_entry.name().to_string()));
            functions.insert(address, function);
        }

        Ok(il::Program::new(functions))
    }
}