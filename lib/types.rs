//! Useful types used across multiple Falcon modules.

use translator;

/// The underlying endianness of this memory model.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum Endian {
    Big,
    Little
}

/// Supported architectures
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum Architecture {
    X86,
    Mips
}


impl Architecture {
    pub fn endian(&self) -> Endian {
        match *self {
            Architecture::X86 => Endian::Little,
            Architecture::Mips => Endian::Big
        }
    }

    pub fn translator(&self) -> Box<translator::Translator> {
        match *self {
            Architecture::X86 => Box::new(translator::x86::X86::new()),
            Architecture::Mips => Box::new(translator::mips::Mips::new())
        }
    }
}