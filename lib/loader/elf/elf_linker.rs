use crate::architecture::*;
use crate::loader::*;
use crate::memory::backing::Memory;
use crate::Error;
use log::warn;
use std::collections::BTreeMap;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

/// The address where the first library will be loaded
const DEFAULT_LIB_BASE: u64 = 0x4000_0000;
/// The step in address between where we will load libraries.
const LIB_BASE_STEP: u64 = 0x0200_0000;

// Some MIPS-specific DT entries. This will eventually land in Goblin.
const DT_MIPS_LOCAL_GOTNO: u64 = 0x7000_000a;
const DT_MIPS_GOTSYM: u64 = 0x7000_0013;
const DT_MIPS_SYMTABNO: u64 = 0x7000_0011;

/// A helper to build an ElfLinker using the builder pattern.
#[derive(Clone, Debug)]
pub struct ElfLinkerBuilder {
    filename: PathBuf,
    do_relocations: bool,
    just_interpreter: bool,
    ld_paths: Option<Vec<PathBuf>>,
}

impl ElfLinkerBuilder {
    /// Create a new ElfLinker
    pub fn new(filename: PathBuf) -> ElfLinkerBuilder {
        ElfLinkerBuilder {
            filename,
            do_relocations: true,
            just_interpreter: false,
            ld_paths: None,
        }
    }

    /// This ElfLinker should perform relocations (default true)
    pub fn do_relocations(mut self, do_relocations: bool) -> Self {
        self.do_relocations = do_relocations;
        self
    }

    /// This ElfLinker should only link in the program interpreter, specified
    /// by DT_INTERPRETER (default false)
    pub fn just_interpreter(mut self, just_interpreter: bool) -> Self {
        self.just_interpreter = just_interpreter;
        self
    }

    /// Set the paths where the ElfLinker should look for shared objects and
    /// depenedncies
    pub fn ld_paths<P: Into<PathBuf>>(mut self, ld_paths: Option<Vec<P>>) -> Self {
        self.ld_paths = ld_paths.map(|v| v.into_iter().map(|p| p.into()).collect::<Vec<PathBuf>>());
        self
    }

    /// Get the ElfLinker for this ElfLinkerBuilder
    pub fn link(self) -> Result<ElfLinker, Error> {
        ElfLinker::new(
            self.filename,
            self.do_relocations,
            self.just_interpreter,
            self.ld_paths,
        )
    }
}

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
    do_relocations: bool,
    /// If set, we will only bring in the DT_INTERPRETER entry, as would happen
    /// if a process was loaded normally.
    just_interpreter: bool,
    /// The paths where ElfLinker will look for dependencies
    ld_paths: Option<Vec<PathBuf>>,
}

impl ElfLinker {
    /// Create a new ElfLinker.
    ///
    /// It is recommended you use ElfLinkerBuilder to build an ElfLinker.
    pub fn new(
        filename: PathBuf,
        do_relocations: bool,
        just_interpreter: bool,
        ld_paths: Option<Vec<PathBuf>>,
    ) -> Result<ElfLinker, Error> {
        let mut file = File::open(&filename)?;
        let mut buf = Vec::new();
        file.read_to_end(&mut buf)?;

        // get the endianness of this elf for the memory model
        let mut endian = Endian::Big;
        if let goblin::Object::Elf(elf_peek) = goblin::Object::parse(&buf)? {
            if elf_peek.header.endianness()?.is_little() {
                endian = Endian::Little;
            }
        } else {
            return Err(Error::InvalidFileFormat(format!(
                "{} was not an elf",
                filename.to_str().unwrap()
            )));
        }

        let mut elf_linker = ElfLinker {
            filename: filename.clone(),
            loaded: BTreeMap::new(),
            memory: Memory::new(endian),
            symbols: BTreeMap::new(),
            next_lib_address: DEFAULT_LIB_BASE,
            user_functions: Vec::new(),
            do_relocations,
            just_interpreter,
            ld_paths,
        };

        elf_linker.load_elf(&filename, 0)?;

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
    pub fn load_elf(&mut self, filename: &Path, base_address: u64) -> Result<(), Error> {
        let path = self
            .ld_paths
            .as_ref()
            .map(|ld_paths| {
                ld_paths
                    .iter()
                    .map(|ld_path| {
                        let filename = if filename.starts_with("/") {
                            let filename = filename.to_str().unwrap();
                            Path::new(filename.split_at(1).1)
                        } else {
                            filename
                        };
                        ld_path.to_path_buf().join(filename)
                    })
                    .find(|path| path.exists())
                    .unwrap_or_else(|| filename.to_path_buf())
            })
            .unwrap_or_else(|| filename.to_path_buf());

        let elf = Elf::from_file_with_base_address(&path, base_address)?;

        // Update our memory map based on what's in the Elf
        for (address, section) in elf.memory()?.sections() {
            self.memory
                .set_memory(*address, section.data().to_owned(), section.permissions());
        }

        // Add this Elf to the loaded Elfs
        let filename = filename.file_name().unwrap().to_str().unwrap().to_string();
        self.loaded.insert(filename.clone(), elf);

        {
            let elf = &self.loaded[&filename];

            // Add its exported symbols to our symbols
            for symbol in elf.exported_symbols() {
                if self.symbols.get(symbol.name()).is_some() {
                    continue;
                }
                self.symbols.insert(
                    symbol.name().to_string(),
                    elf.base_address() + symbol.address(),
                );
            }
        }

        if self.just_interpreter {
            let interpreter_filename = self.loaded[&filename]
                .elf()
                .interpreter
                .map(|s| s.to_string());
            if let Some(interpreter_filename) = interpreter_filename {
                self.load_elf(Path::new(&interpreter_filename), DEFAULT_LIB_BASE)?;
            }
        } else {
            // Ensure all shared objects we rely on are loaded
            for so_name in self.loaded[&filename].dt_needed()? {
                if self.loaded.get(&so_name).is_none() {
                    self.next_lib_address += LIB_BASE_STEP;
                    let next_lib_address = self.next_lib_address;
                    self.load_elf(Path::new(&so_name), next_lib_address)?;
                }
            }
        }

        if self.do_relocations {
            match self.loaded[&filename].elf().header.e_machine {
                goblin::elf::header::EM_386 => self.relocations_x86(&filename)?,
                goblin::elf::header::EM_MIPS => self.relocations_mips(&filename)?,
                _ => return Err(Error::ElfLinkerRelocationsUnsupported),
            }
        }

        Ok(())
    }

    /// Get the `Elf` for the primary elf loaded.
    pub fn get_elf(&self) -> Result<&Elf, Error> {
        let loaded = self.loaded();
        let filename = self
            .filename()
            .file_name()
            .and_then(|filename| filename.to_str())
            .ok_or("Could not get filename for ElfLinker's primary program")?;

        let elf = loaded
            .get(filename)
            .ok_or(format!("Could not get {} from ElfLinker", filename))?;

        Ok(elf)
    }

    /// If the primary `Elf` we're loading has an interpreter designated in its
    /// dynamic sectino, get the `Elf` for the interpreter.
    pub fn get_interpreter(&self) -> Result<Option<&Elf>, Error> {
        let elf = self.get_elf()?;

        let interpreter_elf = match elf.elf().interpreter {
            Some(interpreter_filename) => {
                let interpreter_filename = Path::new(interpreter_filename)
                    .file_name()
                    .and_then(|filename| filename.to_str())
                    .ok_or_else(|| {
                        Error::Custom(
                            "Failed to get filename portion of interpreter filename".to_string(),
                        )
                    })?;
                Some(self.loaded().get(interpreter_filename).ok_or(format!(
                    "Could not find interpreter {}",
                    interpreter_filename
                ))?)
            }
            None => None,
        };

        Ok(interpreter_elf)
    }

    /// Perform x86-specific relocations
    fn relocations_x86(&mut self, filename: &str) -> Result<(), Error> {
        // Process relocations
        let elf = &self.loaded[filename];
        let dynsyms = elf.elf().dynsyms;
        let dynstrtab = elf.elf().dynstrtab;
        for reloc in elf
            .elf()
            .dynrelas
            .iter()
            .chain(elf.elf().dynrels.iter().chain(elf.elf().pltrelocs.iter()))
        {
            match reloc.r_type {
                goblin::elf::reloc::R_386_32 => {
                    let sym = &dynsyms
                        .get(reloc.r_sym)
                        .expect("Unable to resolve relocation symbol");
                    let sym_name = &dynstrtab[sym.st_name];
                    let value = match self.symbols.get(sym_name) {
                        Some(v) => v.to_owned() as u32,
                        None => {
                            return Err(Error::Custom(format!(
                                "Could not resolve symbol {}",
                                sym_name
                            )))
                        }
                    };
                    self.memory
                        .set32(reloc.r_offset + elf.base_address(), value)?;
                }
                goblin::elf::reloc::R_386_GOT32 => {
                    return Err(Error::Custom("R_386_GOT32".to_string()))
                }
                goblin::elf::reloc::R_386_PLT32 => {
                    let sym = &dynsyms
                        .get(reloc.r_sym)
                        .expect("Unable to resolve relocation symbol");
                    let sym_name = &dynstrtab[sym.st_name];
                    return Err(Error::Custom(format!(
                        "R_386_PLT32 {:?}:0x{:x}:{}",
                        self.filename, reloc.r_offset, sym_name
                    )));
                }
                goblin::elf::reloc::R_386_COPY => {
                    return Err(Error::Custom("R_386_COPY".to_string()))
                }
                goblin::elf::reloc::R_386_GLOB_DAT => {
                    let sym = &dynsyms
                        .get(reloc.r_sym)
                        .expect("Unable to resolve relocation symbol");
                    let sym_name = &dynstrtab[sym.st_name];
                    let value = match self.symbols.get(sym_name) {
                        Some(v) => v.to_owned() as u32,
                        None => {
                            warn!("Could not resolve symbol {}", sym_name);
                            continue;
                        }
                    };
                    self.memory
                        .set32(reloc.r_offset + elf.base_address(), value)?;
                }
                goblin::elf::reloc::R_386_JMP_SLOT => {
                    let sym = &dynsyms
                        .get(reloc.r_sym)
                        .expect("Unable to resolve relocation symbol");
                    let sym_name = &dynstrtab[sym.st_name];
                    let value = match self.symbols.get(sym_name) {
                        Some(v) => v.to_owned() as u32,
                        None => {
                            return Err(Error::Custom(format!(
                                "Could not resolve symbol {}",
                                sym_name
                            )))
                        }
                    };
                    self.memory
                        .set32(reloc.r_offset + elf.base_address(), value)?;
                }
                goblin::elf::reloc::R_386_RELATIVE => {
                    let value = self.memory.get32(reloc.r_offset + elf.base_address());
                    let value = match value {
                        Some(value) => elf.base_address() as u32 + value,
                        None => {
                            return Err(Error::Custom(format!(
                                "Invalid address for R_386_RELATIVE {:?}:{:x}",
                                self.filename, reloc.r_offset,
                            )))
                        }
                    };
                    self.memory
                        .set32(reloc.r_offset + elf.base_address(), value)?;
                }
                goblin::elf::reloc::R_386_GOTPC => {
                    return Err(Error::Custom("R_386_GOT_PC".to_string()))
                }
                goblin::elf::reloc::R_386_TLS_TPOFF => {
                    return Err(Error::Custom(
                        "Ignoring R_386_TLS_TPOFF Relocation".to_string(),
                    ))
                }
                goblin::elf::reloc::R_386_IRELATIVE => {
                    return Err(Error::Custom(format!(
                        "R_386_IRELATIVE {:?}:0x{:x} going unprocessed",
                        self.filename, reloc.r_offset
                    )))
                }
                _ => {
                    return Err(Error::Custom(format!(
                        "unhandled relocation type {}",
                        reloc.r_type
                    )))
                }
            }
        }
        Ok(())
    }

    /// Perform MIPS-specific relocations
    fn relocations_mips(&mut self, filename: &str) -> Result<(), Error> {
        let elf = &self.loaded[filename];

        fn get_dynamic(elf: &Elf, tag: u64) -> Option<u64> {
            elf.elf().dynamic.and_then(|dynamic| {
                dynamic
                    .dyns
                    .iter()
                    .find(|dyn_| dyn_.d_tag == tag)
                    .map(|dyn_| dyn_.d_val)
            })
        }

        // The number of local GOT entries. Also an index into the GOT
        // for the first external GOT entry.
        let local_gotno =
            get_dynamic(elf, DT_MIPS_LOCAL_GOTNO).ok_or("Could not get DT_MIPS_LOCAL_GOTNO")?;

        // Index of the first dynamic symbol table entry that corresponds
        // to an entry in the GOT.
        let gotsym = get_dynamic(elf, DT_MIPS_GOTSYM).ok_or("Could not get DT_MIPS_GOTSYM")?;

        // The number of entries in the dynamic symbol table
        let symtabno =
            get_dynamic(elf, DT_MIPS_SYMTABNO).ok_or("Could not get DT_MIPS_SYMTABNO")?;

        // The address of the GOT section
        let pltgot =
            get_dynamic(elf, goblin::elf::dynamic::DT_PLTGOT).ok_or("Could not get DT_PLTGOT")?;

        // Start by adding the base address to all entries in the GOT
        for i in 0..(local_gotno + (symtabno - gotsym)) {
            let address = elf.base_address() + (i * 4) + pltgot;
            let value = self.memory.get32(address).ok_or(format!(
                "Could not get memory at address 0x{:x} for adding base address",
                address
            ))?;
            self.memory
                .set32(address, value.wrapping_add(elf.base_address() as u32))?;
        }

        let dynstrtab = elf.elf().dynstrtab;
        let dynsyms = elf.elf().dynsyms;
        let mut address = pltgot + elf.base_address() + (local_gotno * 4);
        for i in gotsym..(symtabno) {
            let sym = dynsyms
                .get(i as usize)
                .ok_or(format!("Could not get symbol {}", i))?;
            let symbol_name = dynstrtab
                .get_at(sym.st_name)
                .ok_or(format!("Could not get symbol name for {}", i))?;
            // Internal entries have already been relocated, so we only need to
            // relocate external entries
            if sym.st_shndx == 0 {
                if let Some(value) = self.symbols.get(symbol_name) {
                    self.memory.set32(address, *value as u32)?;
                } else {
                    format!("Could not get symbol with name: \"{}\"", symbol_name);
                }
            }
            address += 4;
        }

        // handle all relocation entries
        for dynrel in elf.elf().dynrels.iter() {
            if dynrel.r_type == goblin::elf::reloc::R_MIPS_REL32 {
                let value = self
                    .memory
                    .get32(dynrel.r_offset + elf.base_address())
                    .ok_or(format!(
                        "Could not load R_MIPS_REL32 at 0x{:x}",
                        dynrel.r_offset + elf.base_address()
                    ))?;
                self.memory.set32(
                    dynrel.r_offset + elf.base_address(),
                    value + (elf.base_address() as u32),
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
    fn memory(&self) -> Result<Memory, Error> {
        Ok(self.memory.clone())
    }

    fn function_entries(&self) -> Result<Vec<FunctionEntry>, Error> {
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
        let filename = self
            .filename
            .as_path()
            .file_name()
            .unwrap()
            .to_str()
            .unwrap();
        self.loaded[filename].program_entry()
    }

    fn architecture(&self) -> &dyn Architecture {
        let filename = self
            .filename
            .as_path()
            .file_name()
            .unwrap()
            .to_str()
            .unwrap();
        self.loaded[filename].architecture()
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn symbols(&self) -> Vec<Symbol> {
        self.loaded
            .iter()
            .flat_map(|(_, elf)| elf.symbols())
            .collect()
    }
}
