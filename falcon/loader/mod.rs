//! Loading executable binaries into Falcon

pub mod elf;
pub mod memory;

use error::*;

enum Architecture {
    X86
}


#[derive(Clone, Debug, PartialEq)]
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


/// Generic trait for all loaders
trait Loader {
    /// Get a model of the memory contained in the binary
    fn memory(&self) -> Result<memory::Memory>;

    /// Get addresses for known function entries
    fn function_entries(&self) -> Result<Vec<FunctionEntry>>;

    /// Get the architecture of the binary
    fn architecture(&self) -> Result<Architecture>;
}
