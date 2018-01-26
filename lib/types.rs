//! Useful types used across multiple Falcon modules.

use analysis::calling_convention::{CallingConvention, CallingConventionType};
use il;
use translator;

/// A boolean type with an unknown value
pub enum PartialBoolean {
    True,
    False,
    Unknown
}

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
    Mips,
    Mipsel
}


impl Architecture {
    /// Get the endianness of the given architecture.
    pub fn endian(&self) -> Endian {
        match *self {
            Architecture::X86 |
            Architecture::Mipsel => Endian::Little,
            Architecture::Mips => Endian::Big,
        }
    }

    /// Get the translator/lifter for this architecture.
    pub fn translator(&self) -> Box<translator::Translator> {
        match *self {
            Architecture::X86 => Box::new(translator::x86::X86::new()),
            Architecture::Mips => Box::new(translator::mips::Mips::new()),
            Architecture::Mipsel => Box::new(translator::mips::Mipsel::new())
        }
    }

    /// Get the default calling convention for this Architecture
    pub fn calling_convention(&self) -> CallingConvention {
        match *self {
            Architecture::Mips |
            Architecture::Mipsel =>
                CallingConvention::new(CallingConventionType::MipsSystemV),
            Architecture::X86 =>
                CallingConvention::new(CallingConventionType::Cdecl),
        }
    }

    /// Get the stack pointer for this architecture
    pub fn stack_pointer(&self) -> il::Scalar {
        match *self {
            Architecture::Mips |
            Architecture::Mipsel => il::scalar("$sp", 32),
            Architecture::X86 => il::scalar("esp", 32)
        }
    }

    /// Get the natural word size of the architecture
    pub fn word_size(&self) -> usize {
        match *self {
            Architecture::Mips |
            Architecture::Mipsel |
            Architecture::X86 => 32
        }
    }
}


#[test]
fn test_x86() {
    let arch = Architecture::X86;
    assert_eq!(arch.endian(), Endian::Little);
    assert_eq!(arch.stack_pointer(), il::scalar("esp", 32));
    assert_eq!(*arch.calling_convention()
                    .return_register(), il::scalar("eax", 32));
}

#[test]
fn test_mips() {
    let arch = Architecture::Mips;
    assert_eq!(arch.endian(), Endian::Big);
    assert_eq!(arch.stack_pointer(), il::scalar("$sp", 32));
    assert_eq!(*arch.calling_convention()
                    .return_register(), il::scalar("$v0", 32));
}

#[test]
fn test_mipsel() {
    let arch = Architecture::Mipsel;
    assert_eq!(arch.endian(), Endian::Little);
    assert_eq!(arch.stack_pointer(), il::scalar("$sp", 32));
    assert_eq!(*arch.calling_convention()
                    .return_register(), il::scalar("$v0", 32));
}
