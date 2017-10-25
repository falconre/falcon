//! ELF Linker/Loader

use error::*;
use goblin;
use goblin::Hint;
use loader::*;
use loader::memory::*;
use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use types::Endian;

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


/// The address where the first library will be loaded
const DEFAULT_LIB_BASE: u64 = 0x8000_0000;
/// The step in address between where we will load libraries.
const LIB_BASE_STEP: u64    = 0x0400_0000;


/// Loads and links multiple ELFs together
#[derive(Clone, Debug)]
pub struct ElfLinker {
    /// The filename (path included) of the file we're loading.
    filename: PathBuf,
    /// A mapping from lib name (for example `libc.so.6`) to Elf.
    loaded: BTreeMap<String, Elf>,
    /// The current memory mapping.
    memory: Memory,
    /// A mapping of function symbol names to addresses
    symbols: BTreeMap<String, u64>,
    /// The address we will place the next library at.
    next_lib_address: u64,
    /// Functions as specified by the user
    user_functions: Vec<u64>
}


impl ElfLinker {
    /// Takes a path to an Elf and loads the Elf, its dependencies, and links
    /// them together.
    pub fn new(filename: &Path) -> Result<ElfLinker> {
        let mut file = File::open(filename)?;
        let mut buf = Vec::new();
        file.read_to_end(&mut buf)?;
        let mut endian = Endian::Big;
        if let goblin::Object::Elf(elf_peek) = goblin::Object::parse(&buf)? {
            if elf_peek.header.endianness()?.is_little() {
                endian = Endian::Little;
            }
        }
        else {
            bail!(format!("{} was not an Elf", filename.to_str().unwrap()));
        }

        let mut elf_linker = ElfLinker {
            filename: filename.to_owned(),
            loaded: BTreeMap::new(),
            memory: Memory::new(endian),
            symbols: BTreeMap::new(),
            next_lib_address: DEFAULT_LIB_BASE,
            user_functions: Vec::new(),
        };

        elf_linker.load_elf(filename, 0)?;

        Ok(elf_linker)
    }


    /// Takes the path to an Elf, and a base address the Elf should be loaded
    /// at. Loads the Elf, all it's dependencies (DT_NEEDED), and then handles
    /// the supported relocations.
    pub fn load_elf(&mut self, filename: &Path, base_address: u64)
        -> Result<()> {

        // Does this file exist in the same directory as the original file?
        let mut base_path = match self.filename.as_path().parent() {
            Some(base_path) => base_path.to_path_buf(),
            None => PathBuf::new()
        };
        base_path.push(filename);

        let filename = if base_path.exists() {
            &base_path
        }
        else {
            filename
        };
        
        info!("Loading {} with base_address 0x{:x}",
            filename.to_str().unwrap(),
            base_address);
        let elf = Elf::from_file_with_base_address(filename, base_address)?;


        // Update our memory map based on what's in the Elf
        for segment in elf.memory()?.segments() {
            self.memory.add_segment(segment.1.clone());
        }

        // Add this Elf to the loaded Elfs
        let filename = filename.file_name()
                               .unwrap()
                               .to_str()
                               .unwrap()
                               .to_string();
        self.loaded.insert(filename.clone(), elf);

        {
            let ref elf = self.loaded[&filename];

            // Add its exported symbols to our symbols
            for symbol in elf.exported_symbols() {
                if self.symbols.get(symbol.name()).is_some() {
                    continue;
                }
                self.symbols.insert(
                    symbol.name().to_string(),
                    elf.base_address() + symbol.address()
                );
            }
        }

        // Ensure all shared objects we rely on are loaded
        for so_name in self.loaded[&filename].dt_needed()?.clone() {
            if self.loaded.get(&so_name).is_none() {
                self.next_lib_address += LIB_BASE_STEP;
                let next_lib_address = self.next_lib_address;
                self.load_elf(Path::new(&so_name), next_lib_address)?;
            }
        }

        match self.loaded[&filename].elf().header.e_machine {
            goblin::elf::header::EM_386 => self.relocations_x86(&filename)?,
            _ => bail!("relocations unsupported for target architecture")
        }

        Ok(())
    }

    fn relocations_x86(&mut self, filename: &str) -> Result<()> {

        // Process relocations
        let ref elf = self.loaded[filename];
        let dynsyms = elf.elf().dynsyms;
        let dynstrtab = elf.elf().dynstrtab;
        for reloc in elf.elf()
                        .dynrelas
                        .iter()
                        .chain(elf.elf()
                                  .dynrels
                                  .iter()
                                  .chain(elf.elf()
                                            .pltrelocs
                                            .iter())) {
            match reloc.r_type {
                goblin::elf::reloc::R_386_32 => {
                    let ref sym = dynsyms[reloc.r_sym];
                    let sym_name = &dynstrtab[sym.st_name];
                    let value = match self.symbols.get(sym_name) {
                        Some(v) => v.to_owned() as u32,
                        None => bail!("Could not resolve symbol {}", sym_name)
                    };
                    self.memory.set_u32_le(
                        reloc.r_offset as u64 + elf.base_address(),
                        value
                    )?;
                }
                goblin::elf::reloc::R_386_GOT32 => {
                    bail!("R_386_GOT32");
                },
                goblin::elf::reloc::R_386_PLT32 => {
                    let ref sym = dynsyms[reloc.r_sym];
                    let sym_name = &dynstrtab[sym.st_name];
                    bail!("R_386_PLT32 {:?}:0x{:x}:{}", self.filename, reloc.r_offset, sym_name);
                },
                goblin::elf::reloc::R_386_COPY => {
                    bail!("R_386_COPY");
                },
                goblin::elf::reloc::R_386_GLOB_DAT => {
                    let ref sym = dynsyms[reloc.r_sym];
                    let sym_name = &dynstrtab[sym.st_name];
                    let value = match self.symbols.get(sym_name) {
                        Some(v) => v.to_owned() as u32,
                        None => {
                            warn!("Could not resolve symbol {}", sym_name);
                            continue
                        }
                    };
                    self.memory.set_u32_le(
                        reloc.r_offset as u64 + elf.base_address(),
                        value
                    )?;
                },
                goblin::elf::reloc::R_386_JMP_SLOT => {
                    let ref sym = dynsyms[reloc.r_sym];
                    let sym_name = &dynstrtab[sym.st_name];
                    let value = match self.symbols.get(sym_name) {
                        Some(v) => v.to_owned() as u32,
                        None => bail!("Could not resolve symbol {}", sym_name)
                    };
                    self.memory.set_u32_le(
                        reloc.r_offset as u64 + elf.base_address(),
                        value
                    )?;
                },
                goblin::elf::reloc::R_386_RELATIVE => {
                    let value = self.memory.get_u32_le(reloc.r_offset as u64 + elf.base_address());
                    let value = match value {
                        Some(value) => elf.base_address() as u32 + value,
                        None => bail!("Invalid address for R_386_RELATIVE {:?}:{:x}",
                                      self.filename,
                                      reloc.r_offset)
                    };
                    self.memory.set_u32_le(reloc.r_offset as u64 + elf.base_address(), value)?;
                },
                goblin::elf::reloc::R_386_GOTPC => {
                    bail!("R_386_GOT_PC");
                },
                goblin::elf::reloc::R_386_TLS_TPOFF => {
                    warn!("Ignoring R_386_TLS_TPOFF Relocation");
                },
                goblin::elf::reloc::R_386_IRELATIVE => {
                    warn!("R_386_IRELATIVE {:?}:0x{:x} going unprocessed", self.filename, reloc.r_offset);
                }
                _ => bail!("unhandled relocation type {}", reloc.r_type)
            }
        }
        Ok(())
    }

    /// Inform the linker of a function at the given address.
    ///
    /// This function will be added to calls to `function_entries` and will be automatically
    /// lifted when calling `to_program`.
    pub fn add_user_function(&mut self, address: u64) {
        self.user_functions.push(address);
    }
}


impl Loader for ElfLinker {
    fn memory(&self) -> Result<memory::Memory> {
        Ok(self.memory.clone())
    }

    fn function_entries(&self) -> Result<Vec<FunctionEntry>> {
        let mut function_entries = Vec::new();
        for loaded in &self.loaded {
            // let fe = loaded.1.function_entries()?;
            // for e in &fe {
            //     println!("{} 0x{:x}", loaded.0, e.address());
            // }
            function_entries.append(&mut loaded.1.function_entries()?);
        }
        for address in &self.user_functions {
            function_entries.push(FunctionEntry::new(*address, None));
        }
        Ok(function_entries)
    }

    // TODO Just maybe a bit too much unwrapping here.
    fn program_entry(&self) -> u64 {
        let filename = self.filename
                           .as_path()
                           .file_name()
                           .unwrap()
                           .to_str()
                           .unwrap();
        self.loaded[filename].program_entry()
    }

    fn architecture(&self) -> Result<Architecture> {
        let filename = self.filename
                           .as_path()
                           .file_name()
                           .unwrap()
                           .to_str()
                           .unwrap();
        self.loaded[filename].architecture()
    }
}



#[derive(Clone, Debug)]
struct ElfSymbol {
    name: String,
    address: u64
}


impl ElfSymbol {
    fn new<S: Into<String>>(name: S, address: u64) -> ElfSymbol {
        ElfSymbol {
            name: name.into(),
            address: address
        }
    }


    fn name(&self) -> &str {
        &self.name
    }


    fn address(&self) -> u64 {
        self.address
    }
}


/// Loads a single ELf.
#[derive(Clone, Debug)]
pub struct Elf {
    base_address: u64,
    bytes: Vec<u8>,
    user_function_entries: Vec<u64>
}


impl Elf {
    /// Create a new Elf from the given bytes. This Elf will be rebased to the given
    /// base address.
    pub fn new(bytes: Vec<u8>, base_address: u64) -> Result<Elf> {
        let peek_bytes: [u8; 16] = clone_into_array(&bytes[0..16]);
        // Load this Elf

        let elf = match goblin::peek_bytes(&peek_bytes)? {
            Hint::Elf(_) => Elf {
                base_address: base_address,
                bytes: bytes,
                user_function_entries: Vec::new()
            },
            _ => return Err("Not a valid elf".into())
        };

        Ok(elf)
    }

    /// Get the base address of this Elf where it has been loaded into loader
    /// memory.
    pub fn base_address(&self) -> u64 {
        self.base_address
    }


    /// Load an Elf from a file and use the given base address.
    pub fn from_file_with_base_address(filename: &Path, base_address: u64)
        -> Result<Elf> {
        let mut file = match File::open(filename) {
            Ok(file) => file,
            Err(e) => return Err(format!(
                "Error opening {}: {}",
                filename.to_str().unwrap(),
                e).into())
        };
        let mut buf = Vec::new();
        file.read_to_end(&mut buf)?;
        Elf::new(buf, base_address)
    }

    /// Load an elf from a file and use the base address of 0.
    pub fn from_file(filename: &Path) -> Result<Elf> {
        Elf::from_file_with_base_address(filename, 0)
    }

    /// Allow the user to manually specify a function entry
    pub fn add_user_function(&mut self, address: u64) {
        self.user_function_entries.push(address);
    }

    /// Return the strings from the DT_NEEDED entries.
    pub fn dt_needed(&self) -> Result<Vec<String>> {
        let mut v = Vec::new();

        let elf = self.elf();
        if let Some(dynamic) = elf.dynamic {
            // We need that strtab, and we have to do this one manually.
            // Get the strtab address
            let mut strtab_address = None;
            for dyn in &dynamic.dyns {
                if dyn.d_tag == goblin::elf::dyn::DT_STRTAB {
                    strtab_address = Some(dyn.d_val);
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
                if    section_header.sh_addr > 0 
                   && section_header.sh_addr <= strtab_address
                   && section_header.sh_addr + section_header.sh_size > strtab_address {
                    let start = section_header.sh_offset + (strtab_address - section_header.sh_addr);
                    let size = section_header.sh_size - (start - section_header.sh_offset);
                    let start = start as usize;
                    let size = size as usize;
                    let strtab_bytes = self.bytes.get(start..(start + size)).unwrap();
                    let strtab = goblin::strtab::Strtab::new(&strtab_bytes, 0);
                    for dyn in dynamic.dyns {
                        if dyn.d_tag == goblin::elf::dyn::DT_NEEDED {
                            let so_name = &strtab[dyn.d_val as usize];
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
    fn elf(&self) -> goblin::elf::Elf {
        goblin::elf::Elf::parse(&self.bytes).unwrap()
    }

    /// Return all symbols exported from this Elf
    fn exported_symbols(&self) -> Vec<ElfSymbol> {
        let mut v = Vec::new();
        let elf = self.elf();
        for sym in elf.dynsyms {
            if sym.st_value == 0 {
                continue;
            }
            if    sym.st_bind() == goblin::elf::sym::STB_GLOBAL
               || sym.st_bind() == goblin::elf::sym::STB_WEAK {
                v.push(ElfSymbol::new(&elf.dynstrtab[sym.st_name], sym.st_value));
            }
        }

        v
    }
}



impl Loader for Elf {
    fn memory(&self) -> Result<Memory> {
        let elf = self.elf();
        let mut memory = Memory::new(self.architecture()?.endian());

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
                
                let segment = MemorySegment::new(
                    ph.p_vaddr + self.base_address,
                    bytes,
                    permissions
                );

                memory.add_segment(segment);
            }
        }

        Ok(memory)
    }


    fn function_entries(&self) -> Result<Vec<FunctionEntry>> {
        let elf = self.elf();

        let mut function_entries = Vec::new();

        let mut functions_added: BTreeSet<u64> = BTreeSet::new();

        // dynamic symbols
        for sym in &elf.dynsyms {
            if sym.is_function() && sym.st_value != 0 {
                let name = &elf.dynstrtab[sym.st_name];
                function_entries.push(FunctionEntry::new(
                    sym.st_value + self.base_address,
                    Some(name.to_string())
                ));
                functions_added.insert(sym.st_value);
            }
        }

        // normal symbols
        for sym in &elf.syms {
            if sym.is_function() && sym.st_value != 0 {
                let name = &elf.strtab[sym.st_name];
                function_entries.push(FunctionEntry::new(
                    sym.st_value + self.base_address,
                    Some(name.to_string()))
                );
                functions_added.insert(sym.st_value);
            }
        }


        if !functions_added.contains(&elf.header.e_entry) {
            function_entries.push(FunctionEntry::new(
                elf.header.e_entry + self.base_address,
                None
            ));
        }

        for user_function_entry in &self.user_function_entries {
            if functions_added.get(&(user_function_entry + self.base_address)).is_some() {
                continue;
            }

            function_entries.push(FunctionEntry::new(
                user_function_entry + self.base_address,
                Some(format!("user_function_{:x}", user_function_entry))
            ));
        }

        Ok(function_entries)
    }


    fn program_entry(&self) -> u64 {
        self.elf().header.e_entry
    }


    fn architecture(&self) -> Result<Architecture> {
        let elf = self.elf();

        if elf.header.e_machine == goblin::elf::header::EM_386 {
            Ok(Architecture::X86)
        }
        else if elf.header.e_machine == goblin::elf::header::EM_MIPS {
            Ok(Architecture::Mips)
        }
        else {
            Err("Unsupported Arcthiecture".into())
        }
    }
}
