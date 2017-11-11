//! Useful types used across multiple Falcon modules.

use il;
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

    pub fn stack_pointer(&self) -> il::Scalar {
        match *self {
            Architecture::X86 => il::scalar("esp", 32),
            Architecture::Mips => il::scalar("$sp", 32)
        }
    }
}


#[test]
fn test_x86() {
    let arch = Architecture::X86;
    assert_eq!(arch.endian(), Endian::Little);
    assert_eq!(arch.stack_pointer(), il::scalar("esp", 32));
}

#[test]
fn test_mips() {
    let arch = Architecture::Mips;
    assert_eq!(arch.endian(), Endian::Big);
    assert_eq!(arch.stack_pointer(), il::scalar("$sp", 32));
}
