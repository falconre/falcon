use error::*;
use goblin;
use goblin::Hint;
use loader::*;
use loader::memory::*;
use std::collections::BTreeSet;
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


#[derive(Clone, Debug)]
pub struct Elf {
    bytes: Vec<u8>
}


impl Elf {
    pub fn new(bytes: Vec<u8>) -> Result<Elf> {
        let peek_bytes: [u8; 16] = clone_into_array(bytes.get(0..16).unwrap());
        match goblin::peek_bytes(&peek_bytes)? {
            Hint::Elf(_) => {
                Ok(Elf {
                    bytes: bytes
                })
            },
            _ => Err("Not a valid elf".into())
        }
    }

    pub fn from_file(filename: &Path) -> Result<Elf> {
        let mut file = File::open(filename)?;
        let mut buf = Vec::new();
        file.read_to_end(&mut buf)?;
        Elf::new(buf)
    }

    fn elf(&self) -> goblin::elf::Elf {
        goblin::elf::Elf::parse(&self.bytes).unwrap()
    }
}



impl Loader for Elf {
    fn memory(&self) -> Result<Memory> {
        let elf = self.elf();
        let mut memory = Memory::new();

        for ph in elf.program_headers {
            if ph.p_type == goblin::elf::program_header::PT_LOAD {
                let file_range = (ph.p_offset as usize)..((ph.p_offset + ph.p_filesz) as usize);
                let mut bytes = self.bytes
                                    .get(file_range)
                                    .ok_or("Malformed Elf")?
                                    .to_vec();

                if bytes.len() != ph.p_memsz as usize {
                    bytes.append(&mut vec![0; (ph.p_memsz - ph.p_filesz) as usize]);
                }

                let mut permissions = NONE;
                if ph.p_flags & goblin::elf::program_header::PF_R != 0 {
                    permissions |= READ;
                }
                if ph.p_flags & goblin::elf::program_header::PF_W != 0 {
                    permissions |= WRITE;
                }
                if ph.p_flags & goblin::elf::program_header::PF_X != 0 {
                    permissions |= EXECUTE;
                }
                
                let segment = MemorySegment::new(ph.p_vaddr, bytes, permissions);

                memory.add_segment(segment);
            }
        }

        Ok(memory)
    }


    fn function_entries(&self) -> Result<Vec<FunctionEntry>> {
        let elf = self.elf();

        let mut function_entries = Vec::new();

        let mut functions_added: BTreeSet<u64> = BTreeSet::new();

        for sym in elf.dynsyms.iter() {
            if sym.is_function() && sym.st_value != 0 {
                let name = elf.dynstrtab.get(sym.st_name).to_string();
                function_entries.push(FunctionEntry::new(sym.st_value, Some(name)));
                functions_added.insert(sym.st_value);
            }
        }

        for sym in elf.syms.iter() {
            if sym.is_function() && sym.st_value != 0 {
                let name = elf.strtab.get(sym.st_name).to_string();
                function_entries.push(FunctionEntry::new(sym.st_value, Some(name)));
                functions_added.insert(sym.st_value);
            }
        }

        if !functions_added.contains(&elf.header.e_entry) {
            function_entries.push(FunctionEntry::new(elf.header.e_entry, None));
        }

        Ok(function_entries)
    }


    fn architecture(&self) -> Result<Architecture> {
        let elf = self.elf();

        if elf.header.e_machine == goblin::elf::header::EM_386 {
            Ok(Architecture::X86)
        }
        else {
            Err("Unsupported Arcthiecture".into())
        }
    }
}
