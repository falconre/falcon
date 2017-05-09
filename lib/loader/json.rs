use base64;
use error::*;
use loader::*;
use loader::memory::*;
use serde_json;
use serde_json::Value;
use std::fs::File;
use std::io::Read;
use std::path::Path;


#[derive(Clone, Debug)]
pub struct Json {
    function_entries: Vec<FunctionEntry>,
    memory: Memory,
    architecture: Architecture
}


impl Json {
    pub fn from_file(filename: &Path) -> Result<Json> {
        let mut file = File::open(filename)?;
        let mut buf = Vec::new();
        file.read_to_end(&mut buf)?;

        let root: Value = serde_json::from_str(&String::from_utf8(buf)?)?;

        let architecture = match root["arch"] {
            Value::String(ref architecture) => {
                if architecture == "x86" {
                    Architecture::X86
                }
                else {
                    bail!("unsupported architecture {}", root["arch"])
                }
            }
            _ => bail!("architecture missing")
        };

        let mut function_entries = Vec::new();
        if let Value::Array(ref functions) = root["functions"] {
            for function in functions {
                let address = match function["address"] {
                    Value::Number(ref address) => match address.as_u64() {
                        Some(address) => address,
                        None => bail!("function address not u64")
                    },
                    _ => bail!("address missing for function")
                };

                let name = match function["name"] {
                    Value::String(ref name) => name.to_string(),
                    _ => bail!("name missing for function")
                };

                function_entries.push(FunctionEntry::new(address, Some(name)));
            }
        }
        else {
            bail!("functions missing");
        }

        let mut memory = Memory::new();
        if let Value::Array(ref segments) = root["segments"] {
            for segment in segments {
                let address = match segment["address"] {
                    Value::Number(ref address) => match address.as_u64() {
                        Some(address) => address,
                        None => bail!("segment address not u64")
                    },
                    _ => bail!("address missing for segment")
                };

                let bytes = match segment["bytes"] {
                    Value::String(ref bytes) => base64::decode(&bytes)?,
                    _ => bail!("bytes missing for segment")
                };

                memory.add_segment(MemorySegment::new(address, bytes, ALL));
            }
        }
        else {
            bail!("segments missing");
        }

        Ok(Json{
            function_entries: function_entries,
            memory: memory,
            architecture: architecture
        })
    }
}



impl Loader for Json {
    fn memory(&self) -> Result<Memory> {
        Ok(self.memory.clone())
    }


    fn function_entries(&self) -> Result<Vec<FunctionEntry>> {
        Ok(self.function_entries.clone())
    }


    fn architecture(&self) -> Result<Architecture> {
        Ok(self.architecture.clone())
    }
}
