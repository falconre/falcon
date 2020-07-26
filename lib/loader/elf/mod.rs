//! ELF Linker/Loader
#[allow(clippy::module_inception)]
mod elf;
mod elf_linker;

pub use self::elf::Elf;
pub use self::elf_linker::{ElfLinker, ElfLinkerBuilder};
