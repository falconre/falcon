//! PE Linker/Loader

use crate::architecture::{Amd64, Mips, X86};
use crate::loader::*;
use crate::memory::backing::Memory;
use crate::memory::MemoryPermissions;
use std::fs::File;
use std::io::Read;
use std::path::Path;

/// Loader for a single PE file.
#[derive(Debug)]
pub struct Pe {
    bytes: Vec<u8>,
    architecture: Box<dyn Architecture>,
}

impl Pe {
    /// Create a new PE from the given bytes. This PE will be rebased to the given
    /// base address.
    pub fn new(bytes: Vec<u8>) -> Result<Pe, Error> {
        let architecture: Box<dyn Architecture> = {
            let pe = goblin::pe::PE::parse(&bytes).map_err(|_| "Not a valid PE")?;

            if pe.header.coff_header.machine == goblin::pe::header::COFF_MACHINE_X86 {
                Box::new(X86::new())
            } else if pe.header.coff_header.machine == goblin::pe::header::COFF_MACHINE_X86_64 {
                Box::new(Amd64::new())
            } else if pe.header.coff_header.machine == goblin::pe::header::COFF_MACHINE_R4000 {
                Box::new(Mips::new())
            } else {
                return Err(Error::UnsupprotedArchitecture);
            }
        };

        Ok(Pe {
            bytes,
            architecture,
        })
    }

    /// Load an PE from a file and use the base address of 0.
    pub fn from_file(filename: &Path) -> Result<Pe, Error> {
        let mut file = match File::open(filename) {
            Ok(file) => file,
            Err(e) => {
                return Err(Error::FalconInternal(format!(
                    "Error opening {}: {}",
                    filename.to_str().unwrap(),
                    e
                )))
            }
        };
        let mut buf = Vec::new();
        file.read_to_end(&mut buf)?;
        Pe::new(buf)
    }

    /// Return the goblin::pe::PE for this PE.
    fn pe(&self) -> goblin::pe::PE {
        goblin::pe::PE::parse(&self.bytes).unwrap()
    }
}

impl Loader for Pe {
    fn memory(&self) -> Result<Memory, Error> {
        let mut memory = Memory::new(self.architecture().endian());

        let pe = self.pe();
        for section in pe.sections {
            let file_offset = section.pointer_to_raw_data as usize;
            let file_size = section.size_of_raw_data as usize;
            let file_bytes = self
                .bytes
                .get(file_offset..(file_offset + file_size))
                .expect("Malformed PE")
                .to_vec();

            let address = section.virtual_address as u64 + pe.image_base as u64;

            let mut permissions = memory::MemoryPermissions::NONE;
            if section.characteristics & goblin::pe::section_table::IMAGE_SCN_MEM_READ != 0 {
                permissions |= MemoryPermissions::READ;
            }
            if section.characteristics & goblin::pe::section_table::IMAGE_SCN_MEM_WRITE != 0 {
                permissions |= MemoryPermissions::WRITE;
            }
            if section.characteristics & goblin::pe::section_table::IMAGE_SCN_MEM_EXECUTE != 0 {
                permissions |= MemoryPermissions::EXECUTE;
            }

            memory.set_memory(address, file_bytes, permissions);
        }

        Ok(memory)
    }

    fn function_entries(&self) -> Result<Vec<FunctionEntry>, Error> {
        let pe = self.pe();

        let mut function_entries = Vec::new();

        for symbol in pe.exports {
            let function_entry = FunctionEntry::new(
                (symbol.rva + pe.image_base) as u64,
                symbol.name.map(|s| s.to_string()),
            );
            function_entries.push(function_entry);
        }

        let entry = pe.entry as u64;

        if !function_entries.iter().any(|fe| fe.address() == entry) {
            function_entries.push(FunctionEntry::new((pe.entry + pe.image_base) as u64, None));
        }

        Ok(function_entries)
    }

    fn program_entry(&self) -> u64 {
        (self.pe().entry + self.pe().image_base) as u64
    }

    fn architecture(&self) -> &dyn Architecture {
        self.architecture.as_ref()
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn symbols(&self) -> Vec<Symbol> {
        let pe = self.pe();
        let mut symbols = Vec::new();
        for export in pe.exports {
            let offset = match export.offset {
                Some(offset) => offset,
                None => continue,
            };
            if let Some(name) = export.name {
                symbols.push(Symbol::new(name.to_string(), offset as u64));
            }
        }
        symbols
    }
}
