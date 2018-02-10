//! ELF Linker/Loader

use goblin;
use goblin::Hint;
use loader::*;
use memory::backing::Memory;
use memory::MemoryPermissions;
use std::fs::File;
use std::io::Read;
use std::path::Path;

// http://stackoverflow.com/questions/37678698/function-to-build-a-fixed-sized-array-from-slice/37679019#37679019
use std::convert::AsMut;

fn clone_into_array<A, T>(slice: &[T]) -> A
    where A: Sized + Default + AsMut<[T]>,
          T: Clone
{
    let mut a = Default::default();
    <A as AsMut<[T]>>::as_mut(&mut a).clone_from_slice(slice);
    a
}


/// Loader for a single ELf file.
#[derive(Clone, Debug)]
pub struct Pe {
    bytes: Vec<u8>
}


impl Pe {
    /// Create a new Elf from the given bytes. This Elf will be rebased to the given
    /// base address.
    pub fn new(bytes: Vec<u8>) -> Result<Pe> {
        let peek_bytes: [u8; 16] = clone_into_array(&bytes[0..16]);
        
        let pe = match goblin::peek_bytes(&peek_bytes)? {
            Hint::PE => Pe {
                bytes: bytes
            },
            _ => return Err("Not a valid PE".into())
        };

        Ok(pe)
    }

    /// Load an elf from a file and use the base address of 0.
    pub fn from_file(filename: &Path) -> Result<Pe> {
        let mut file = match File::open(filename) {
            Ok(file) => file,
            Err(e) => return Err(format!(
                "Error opening {}: {}",
                filename.to_str().unwrap(),
                e).into())
        };
        let mut buf = Vec::new();
        file.read_to_end(&mut buf)?;
        Pe::new(buf)
    }

    /// Return the goblin::elf::Elf for this elf.
    fn pe(&self) -> goblin::pe::PE {
        goblin::pe::PE::parse(&self.bytes).unwrap()
    }
}



impl Loader for Pe {
    fn memory(&self) -> Result<Memory> {
        let mut memory = Memory::new(self.architecture()?.endian());

        let pe = self.pe();
        for section in pe.sections {
            let file_offset = section.pointer_to_raw_data as usize;
            let file_size = section.size_of_raw_data as usize;
            let file_bytes = self.bytes
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


    fn function_entries(&self) -> Result<Vec<FunctionEntry>> {
        let pe = self.pe();

        let mut function_entries = Vec::new();

        for symbol in pe.exports {
            let function_entry = FunctionEntry::new(
                (symbol.rva + pe.image_base) as u64,
                Some(symbol.name.to_string())
            );
            function_entries.push(function_entry);
        }

        let entry = pe.entry as u64;

        if !function_entries.iter().any(|fe| fe.address() == entry) {
            function_entries.push(FunctionEntry::new(
                (pe.entry + pe.image_base) as u64,
                None
            ));
        }

        Ok(function_entries)
    }


    fn program_entry(&self) -> u64 {
        (self.pe().entry + self.pe().image_base) as u64
    }


    fn architecture(&self) -> Result<Architecture> {
        let pe = self.pe();

        if pe.header.coff_header.machine == goblin::pe::header::COFF_MACHINE_X86 {
            Ok(Architecture::X86)
        }
        else {
            Err("Unsupported Architecture".into())
        }
    }
}
