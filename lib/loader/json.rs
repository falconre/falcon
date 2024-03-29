//! Experimental loader which takes a program specification in Json form.

use crate::architecture::*;
use crate::loader::*;
use crate::memory::backing::*;
use crate::memory::MemoryPermissions;
use crate::Error;
use base64::Engine;
use serde_json::Value;
use std::fs::File;
use std::io::Read;
use std::path::Path;

/// Experimental loader which takes a program specification in Json form.
///
/// See the binary ninja script for an example use.
#[derive(Debug)]
pub struct Json {
    function_entries: Vec<FunctionEntry>,
    memory: Memory,
    architecture: Box<dyn Architecture>,
    entry: u64,
}

impl Json {
    /// Create a new `Json` loader from the given file.
    pub fn from_file(filename: &Path) -> Result<Json, Error> {
        let mut file = File::open(filename)?;
        let mut buf = Vec::new();
        file.read_to_end(&mut buf)?;

        let root: Value = serde_json::from_str(&String::from_utf8(buf)?)?;

        let architecture = match root["arch"] {
            Value::String(ref architecture) => {
                if architecture == "x86" {
                    Box::new(X86::new())
                } else {
                    return Err(Error::UnsupprotedArchitecture);
                }
            }
            _ => return Err(Error::UnsupprotedArchitecture),
        };

        let entry = match root["entry"] {
            Value::Number(ref number) => number.as_u64().unwrap(),
            _ => return Err(Error::FalconInternal("entry missing".to_string())),
        };

        let mut function_entries = Vec::new();
        if let Value::Array(ref functions) = root["functions"] {
            for function in functions {
                let address = match function["address"] {
                    Value::Number(ref address) => match address.as_u64() {
                        Some(address) => address,
                        None => {
                            return Err(Error::FalconInternal(
                                "function address not u64".to_string(),
                            ))
                        }
                    },
                    _ => {
                        return Err(Error::FalconInternal(
                            "address missing for function".to_string(),
                        ))
                    }
                };

                let name = match function["name"] {
                    Value::String(ref name) => name.to_string(),
                    _ => {
                        return Err(Error::FalconInternal(
                            "name missing for function".to_string(),
                        ))
                    }
                };

                function_entries.push(FunctionEntry::new(address, Some(name)));
            }
        } else {
            return Err(Error::FalconInternal("functions missing".to_string()));
        }

        let mut memory = Memory::new(architecture.endian());
        if let Value::Array(ref segments) = root["segments"] {
            for segment in segments {
                let address = match segment["address"] {
                    Value::Number(ref address) => match address.as_u64() {
                        Some(address) => address,
                        None => {
                            return Err(Error::FalconInternal(
                                "segment address not u64".to_string(),
                            ))
                        }
                    },
                    _ => {
                        return Err(Error::FalconInternal(
                            "address missing for segment".to_string(),
                        ))
                    }
                };

                let bytes = match segment["bytes"] {
                    Value::String(ref bytes) => {
                        base64::engine::general_purpose::STANDARD_NO_PAD.decode(bytes)?
                    }
                    _ => {
                        return Err(Error::FalconInternal(
                            "bytes missing for segment".to_string(),
                        ))
                    }
                };

                memory.set_memory(address, bytes, MemoryPermissions::ALL);
            }
        } else {
            return Err(Error::FalconInternal("segments missing".to_string()));
        }

        Ok(Json {
            function_entries,
            memory,
            architecture,
            entry,
        })
    }
}

impl Loader for Json {
    fn memory(&self) -> Result<Memory, Error> {
        Ok(self.memory.clone())
    }

    fn function_entries(&self) -> Result<Vec<FunctionEntry>, Error> {
        Ok(self.function_entries.clone())
    }

    fn program_entry(&self) -> u64 {
        self.entry
    }

    fn architecture(&self) -> &dyn Architecture {
        self.architecture.as_ref()
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn symbols(&self) -> Vec<Symbol> {
        Vec::new()
    }
}
