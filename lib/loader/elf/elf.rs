use crate::architecture::*;
use crate::loader::*;
use crate::memory::backing::Memory;
use crate::memory::MemoryPermissions;
use crate::Error;
use std::collections::BTreeMap;
use std::fs::File;
use std::io::Read;
use std::path::Path;

/// Loader for a single ELf file.
#[derive(Debug)]
pub struct Elf {
    base_address: u64,
    bytes: Vec<u8>,
    user_function_entries: Vec<u64>,
    architecture: Box<dyn Architecture>,
}

impl Elf {
    /// Create a new Elf from the given bytes. This Elf will be rebased to the given
    /// base address.
    pub fn new(bytes: Vec<u8>, base_address: u64) -> Result<Elf, Error> {
        let architecture = {
            let elf = goblin::elf::Elf::parse(&bytes).map_err(|_| "Not a valid elf")?;

            if elf.header.e_machine == goblin::elf::header::EM_386 {
                Box::new(X86::new())
            } else if elf.header.e_machine == goblin::elf::header::EM_MIPS {
                match elf.header.endianness()? {
                    goblin::container::Endian::Big => {
                        Box::new(Mips::new()) as Box<dyn Architecture>
                    }
                    goblin::container::Endian::Little => {
                        Box::new(Mipsel::new()) as Box<dyn Architecture>
                    }
                }
            } else if elf.header.e_machine == goblin::elf::header::EM_PPC {
                match elf.header.endianness()? {
                    goblin::container::Endian::Big => Box::new(Ppc::new()) as Box<dyn Architecture>,
                    goblin::container::Endian::Little => {
                        return Err(Error::FalconInternal(
                            "PPC Little-Endian not supported".to_string(),
                        ))
                    }
                }
            } else if elf.header.e_machine == goblin::elf::header::EM_X86_64 {
                Box::new(Amd64::new())
            } else if elf.header.e_machine == goblin::elf::header::EM_AARCH64 {
                match elf.header.endianness()? {
                    goblin::container::Endian::Big => {
                        Box::new(AArch64Eb::new()) as Box<dyn Architecture>
                    }
                    goblin::container::Endian::Little => {
                        Box::new(AArch64::new()) as Box<dyn Architecture>
                    }
                }
            } else {
                return Err(Error::UnsupprotedArchitecture);
            }
        };

        Ok(Elf {
            base_address,
            bytes,
            user_function_entries: Vec::new(),
            architecture,
        })
    }

    /// Get the base address of this Elf where it has been loaded into loader
    /// memory.
    pub fn base_address(&self) -> u64 {
        self.base_address
    }

    /// Load an Elf from a file and use the given base address.
    pub fn from_file_with_base_address<P: AsRef<Path>>(
        filename: P,
        base_address: u64,
    ) -> Result<Elf, Error> {
        let filename: &Path = filename.as_ref();
        let mut file = match File::open(filename) {
            Ok(file) => file,
            Err(e) => {
                return Err(format!("Error opening {:?}: {}", filename.to_string_lossy(), e).into())
            }
        };
        let mut buf = Vec::new();
        file.read_to_end(&mut buf)?;
        Elf::new(buf, base_address)
    }

    /// Load an elf from a file and use the base address of 0.
    pub fn from_file<P: AsRef<Path>>(filename: P) -> Result<Elf, Error> {
        Elf::from_file_with_base_address(filename, 0)
    }

    /// Allow the user to manually specify a function entry
    pub fn add_user_function(&mut self, address: u64) {
        self.user_function_entries.push(address);
    }

    /// Return the strings from the DT_NEEDED entries.
    pub fn dt_needed(&self) -> Result<Vec<String>, Error> {
        let mut v = Vec::new();

        let elf = self.elf();
        if let Some(dynamic) = elf.dynamic {
            // We need that strtab, and we have to do this one manually.
            // Get the strtab address
            let mut strtab_address = None;
            for dyn_ in &dynamic.dyns {
                if dyn_.d_tag == goblin::elf::dynamic::DT_STRTAB {
                    strtab_address = Some(dyn_.d_val);
                    break;
                }
            }
            if strtab_address.is_none() {
                return Ok(v);
            }
            let strtab_address = strtab_address.unwrap();
            // We're going to make a pretty safe assumption that strtab is all
            // in one section
            for section_header in &elf.section_headers {
                if section_header.sh_addr > 0
                    && section_header.sh_addr <= strtab_address
                    && section_header.sh_addr + section_header.sh_size > strtab_address
                {
                    let start =
                        section_header.sh_offset + (strtab_address - section_header.sh_addr);
                    let size = section_header.sh_size - (start - section_header.sh_offset);
                    let start = start as usize;
                    let size = size as usize;
                    let strtab_bytes = self.bytes.get(start..(start + size)).unwrap();
                    let strtab = goblin::strtab::Strtab::new(strtab_bytes, 0);
                    for dyn_ in dynamic.dyns {
                        if dyn_.d_tag == goblin::elf::dynamic::DT_NEEDED {
                            let so_name = &strtab[dyn_.d_val as usize];
                            v.push(so_name.to_string());
                        }
                    }
                    return Ok(v);
                }
            }
            // if we got here, we didn't return a vector (I think ;))
            panic!("Failed to get Dynamic strtab");
        }

        Ok(v)
    }

    /// Return the goblin::elf::Elf for this elf.
    pub fn elf(&self) -> goblin::elf::Elf {
        goblin::elf::Elf::parse(&self.bytes).unwrap()
    }

    /// Return all symbols exported from this Elf
    pub fn exported_symbols(&self) -> Vec<Symbol> {
        let mut v = Vec::new();
        let elf = self.elf();
        for sym in elf.dynsyms.iter() {
            if sym.st_value == 0 || sym.st_shndx == 0 {
                continue;
            }
            if sym.st_bind() == goblin::elf::sym::STB_GLOBAL
                || sym.st_bind() == goblin::elf::sym::STB_WEAK
            {
                v.push(Symbol::new(
                    &elf.dynstrtab[sym.st_name],
                    sym.st_value + self.base_address(),
                ));
            }
        }

        v
    }

    /// Return all symbols for this Elf
    pub fn symbols(&self) -> Vec<Symbol> {
        let elf = self.elf();
        let mut symbols = Vec::new();
        for sym in elf.dynsyms.iter() {
            if sym.st_value == 0 {
                continue;
            }
            symbols.push(Symbol::new(
                &elf.dynstrtab[sym.st_name],
                sym.st_value + self.base_address(),
            ));
        }

        for sym in elf.syms.iter() {
            if sym.st_value == 0 {
                continue;
            }
            symbols.push(Symbol::new(
                &elf.strtab[sym.st_name],
                sym.st_value + self.base_address(),
            ));
        }

        for rel in elf.pltrelocs.iter() {
            let sym = match elf.dynsyms.get(rel.r_sym) {
                Some(sym) => sym,
                None => continue,
            };

            let name = &elf.dynstrtab[sym.st_name];
            symbols.push(Symbol::new(name, rel.r_offset));
        }

        symbols.sort();
        symbols.dedup();
        symbols
    }
}

impl Loader for Elf {
    fn memory(&self) -> Result<Memory, Error> {
        let elf = self.elf();
        let mut memory = Memory::new(self.architecture().endian());

        for ph in elf.program_headers {
            if ph.p_type == goblin::elf::program_header::PT_LOAD {
                let file_range = (ph.p_offset as usize)..((ph.p_offset + ph.p_filesz) as usize);
                let mut bytes = self
                    .bytes
                    .get(file_range)
                    .ok_or_else(|| Error::FalconInternal("Malformed Elf".to_string()))?
                    .to_vec();

                if bytes.len() != ph.p_memsz as usize {
                    bytes.append(&mut vec![0; (ph.p_memsz - ph.p_filesz) as usize]);
                }

                let mut permissions = memory::MemoryPermissions::NONE;
                if ph.p_flags & goblin::elf::program_header::PF_R != 0 {
                    permissions |= MemoryPermissions::READ;
                }
                if ph.p_flags & goblin::elf::program_header::PF_W != 0 {
                    permissions |= MemoryPermissions::WRITE;
                }
                if ph.p_flags & goblin::elf::program_header::PF_X != 0 {
                    permissions |= MemoryPermissions::EXECUTE;
                }

                memory.set_memory(ph.p_vaddr + self.base_address, bytes, permissions);
            }
        }

        Ok(memory)
    }

    fn function_entries(&self) -> Result<Vec<FunctionEntry>, Error> {
        let elf = self.elf();

        let mut function_entries: BTreeMap<u64, FunctionEntry> = BTreeMap::new();

        // dynamic symbols
        for sym in &elf.dynsyms {
            if sym.is_function() && sym.st_value != 0 && sym.st_shndx > 0 {
                let name = &elf.dynstrtab[sym.st_name];
                function_entries.insert(
                    sym.st_value,
                    FunctionEntry::new(sym.st_value + self.base_address, Some(name.to_string())),
                );
            }
        }

        // normal symbols
        for sym in &elf.syms {
            if sym.is_function() && sym.st_value != 0 && sym.st_shndx > 0 {
                let name = &elf.strtab[sym.st_name];
                function_entries.insert(
                    sym.st_value,
                    FunctionEntry::new(sym.st_value + self.base_address, Some(name.to_string())),
                );
            }
        }

        function_entries
            .entry(elf.header.e_entry)
            .or_insert_with(|| FunctionEntry::new(elf.header.e_entry + self.base_address, None));

        for &user_function_entry in &self.user_function_entries {
            if function_entries.contains_key(&user_function_entry) {
                continue;
            }

            function_entries.insert(
                user_function_entry,
                FunctionEntry::new(
                    user_function_entry + self.base_address,
                    Some(format!("user_function_{:x}", user_function_entry)),
                ),
            );
        }

        Ok(function_entries.into_values().collect())
    }

    fn program_entry(&self) -> u64 {
        self.elf().header.e_entry
    }

    fn architecture(&self) -> &dyn Architecture {
        self.architecture.as_ref()
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn symbols(&self) -> Vec<Symbol> {
        self.symbols()
    }
}
