use architecture::*;
use goblin;
use loader::*;
use memory::backing::Memory;
use std::collections::BTreeMap;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};


/// The address where the first library will be loaded
const DEFAULT_LIB_BASE: u64 = 0x4000_0000;
/// The step in address between where we will load libraries.
const LIB_BASE_STEP: u64    = 0x0200_0000;


/// Loader which links together multiple Elf files.
///
/// Can do some rudimentary linking of binaries.
#[derive(Debug)]
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
    user_functions: Vec<u64>,
    /// If set, we will do relocations as we link
    do_relocations: bool
}


impl ElfLinker {
    /// Takes a path to an Elf and loads the Elf, its dependencies, and links
    /// them together.
    pub fn new(filename: &Path, do_relocations: bool) -> Result<ElfLinker> {
        let mut file = File::open(filename)?;
        let mut buf = Vec::new();
        file.read_to_end(&mut buf)?;

        // get the endianness of this elf for the memory model
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
            do_relocations
        };

        elf_linker.load_elf(filename, 0)?;

        Ok(elf_linker)
    }


    /// Get the ELFs loaded and linked in this loader
    pub fn loaded(&self) -> &BTreeMap<String, Elf> {
        &self.loaded
    }


    /// Get the filename of the ELF we're loading
    pub fn filename(&self) -> &Path {
        &self.filename
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
        for (address, section) in elf.memory()?.sections() {
            self.memory.set_memory(*address,
                                   section.data().to_owned(),
                                   section.permissions());
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

        if self.do_relocations {
            match self.loaded[&filename].elf().header.e_machine {
                goblin::elf::header::EM_386 =>
                    self.relocations_x86(&filename)?,
                goblin::elf::header::EM_MIPS =>
                    self.relocations_mips(&filename)?,
                _ => bail!("relocations unsupported for target architecture")
            }
        }

        Ok(())
    }


    fn relocations_x86(&mut self, filename: &str) -> Result<()> {
        // Process relocations
        let ref elf = self.loaded[filename];
        let dynsyms = elf.elf().dynsyms;
        let dynstrtab = elf.elf().dynstrtab;
        for reloc in elf.elf().dynrelas.iter().chain(
            elf.elf().dynrels.iter().chain(
                elf.elf().pltrelocs.iter())) {
            match reloc.r_type {
                goblin::elf::reloc::R_386_32 => {
                    let ref sym = dynsyms.get(reloc.r_sym)
                        .expect("Unable to resolve relocation symbol");
                    let sym_name = &dynstrtab[sym.st_name];
                    let value = match self.symbols.get(sym_name) {
                        Some(v) => v.to_owned() as u32,
                        None => bail!("Could not resolve symbol {}", sym_name)
                    };
                    self.memory.set32(
                        reloc.r_offset as u64 + elf.base_address(),
                        value
                    )?;
                }
                goblin::elf::reloc::R_386_GOT32 => {
                    bail!("R_386_GOT32");
                },
                goblin::elf::reloc::R_386_PLT32 => {
                    let ref sym = dynsyms.get(reloc.r_sym)
                        .expect("Unable to resolve relocation symbol");
                    let sym_name = &dynstrtab[sym.st_name];
                    bail!("R_386_PLT32 {:?}:0x{:x}:{}",
                          self.filename,
                          reloc.r_offset,
                          sym_name);
                },
                goblin::elf::reloc::R_386_COPY => {
                    bail!("R_386_COPY");
                },
                goblin::elf::reloc::R_386_GLOB_DAT => {
                    let ref sym = dynsyms.get(reloc.r_sym)
                        .expect("Unable to resolve relocation symbol");
                    let sym_name = &dynstrtab[sym.st_name];
                    let value = match self.symbols.get(sym_name) {
                        Some(v) => v.to_owned() as u32,
                        None => {
                            warn!("Could not resolve symbol {}", sym_name);
                            continue
                        }
                    };
                    self.memory.set32(
                        reloc.r_offset as u64 + elf.base_address(),
                        value
                    )?;
                },
                goblin::elf::reloc::R_386_JMP_SLOT => {
                    let ref sym = dynsyms.get(reloc.r_sym)
                        .expect("Unable to resolve relocation symbol");
                    let sym_name = &dynstrtab[sym.st_name];
                    let value = match self.symbols.get(sym_name) {
                        Some(v) => v.to_owned() as u32,
                        None => bail!("Could not resolve symbol {}", sym_name)
                    };
                    self.memory.set32(
                        reloc.r_offset as u64 + elf.base_address(),
                        value
                    )?;
                },
                goblin::elf::reloc::R_386_RELATIVE => {
                    let value = self.memory.get32(reloc.r_offset as u64 + elf.base_address());
                    let value = match value {
                        Some(value) => elf.base_address() as u32 + value,
                        None => bail!("Invalid address for R_386_RELATIVE {:?}:{:x}",
                                      self.filename,
                                      reloc.r_offset)
                    };
                    self.memory.set32(reloc.r_offset as u64 + elf.base_address(), value)?;
                },
                goblin::elf::reloc::R_386_GOTPC => {
                    bail!("R_386_GOT_PC");
                },
                goblin::elf::reloc::R_386_TLS_TPOFF => {
                    warn!("Ignoring R_386_TLS_TPOFF Relocation");
                },
                goblin::elf::reloc::R_386_IRELATIVE => {
                    warn!("R_386_IRELATIVE {:?}:0x{:x} going unprocessed",
                          self.filename,
                          reloc.r_offset);
                }
                _ => bail!("unhandled relocation type {}", reloc.r_type)
            }
        }
        Ok(())
    }


    fn relocations_mips(&mut self, filename: &str) -> Result<()> {
        let elf = &self.loaded[filename];

        fn get_dynamic(elf: &Elf, tag: u64) -> Option<u64> {
            elf.elf().dynamic.and_then(|dynamic|
                dynamic.dyns
                    .iter()
                    .find(|dyn| dyn.d_tag == tag)
                    .map(|dyn| dyn.d_val))
        }

        // The number of local GOT entries. Also an index into the GOT
        // for the first external GOT entry.
        let local_gotno =
            get_dynamic(elf, goblin::elf::dyn::DT_MIPS_LOCAL_GOTNO)
            .ok_or("Could not get DT_MIPS_LOCAL_GOTNO")?;

        // Index of the first dynamic symbol table entry that corresponds
        // to an entry in the GOT.
        let gotsym =
            get_dynamic(elf, goblin::elf::dyn::DT_MIPS_GOTSYM)
            .ok_or("Could not get DT_MIPS_GOTSYM")?;

        // The number of entries in the dynamic symbol table
        let symtabno =
            get_dynamic(elf, goblin::elf::dyn::DT_MIPS_SYMTABNO)
            .ok_or("Could not get DT_MIPS_SYMTABNO")?;

        // The address of the GOT section
        let pltgot =
            get_dynamic(elf, goblin::elf::dyn::DT_PLTGOT)
            .ok_or("Could not get DT_PLTGOT")?;

        // Start by adding the base address to all entries in the GOT
        for i in 0..(local_gotno + (symtabno - gotsym)) {
            let address = elf.base_address() + (i * 4) + pltgot;
            let value = self.memory.get32(address)
                .ok_or(format!("Could not get memory at address 0x{:x} for adding base address",
                    address))?;
            self.memory.set32(address, value.wrapping_add(elf.base_address() as u32))?;
        }


        let dynstrtab = elf.elf().dynstrtab;
        let dynsyms = elf.elf().dynsyms;
        let mut address = pltgot + elf.base_address() + (local_gotno * 4);
        for i in gotsym..(symtabno) {
            let sym = dynsyms.get(i as usize)
                .ok_or(format!("Could not get symbol {}", i))?;
            let symbol_name = dynstrtab.get(sym.st_name)
                .ok_or(format!("Could not get symbol name for {}", i))??;
            // Internal entries have already been relocated, so we only need to
            // relocate external entries
            if sym.st_shndx == 0 {
                if let Some(value) = self.symbols.get(symbol_name) {
                    self.memory.set32(address, *value as u32)?;

                    if symbol_name == "_rtld_global" {
                        println!("0x{:08x} symbol {} 0x{:08x} {:02} {} 0x{:x}",
                            address, i, sym.st_value, sym.st_shndx, symbol_name,
                            value);
                    }
                }
                else {
                    format!("Could not get symbol with name: \"{}\"",
                        symbol_name);
                }
            }
            address += 4;
        }

        // handle all relocation entries
        for dynrel in elf.elf().dynrels {
            if dynrel.r_type == goblin::elf::reloc::R_MIPS_REL32 {
                let value =
                    self.memory
                        .get32(dynrel.r_offset + elf.base_address())
                        .ok_or(format!("Could not load R_MIPS_REL32 at 0x{:x}",
                            dynrel.r_offset + elf.base_address()))?;
                self.memory.set32(
                    dynrel.r_offset + elf.base_address(),
                    value + (elf.base_address() as u32)
                )?;
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
    fn memory(&self) -> Result<Memory> {
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

    fn architecture(&self) -> &Architecture {
        let filename = self.filename
                           .as_path()
                           .file_name()
                           .unwrap()
                           .to_str()
                           .unwrap();
        self.loaded[filename].architecture()
    }
}