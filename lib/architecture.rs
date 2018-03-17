use analysis::calling_convention::{CallingConvention, CallingConventionType};
use il;
use std::fmt::Debug;
use translator;



/// The underlying endianness of this memory model.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum Endian {
    Big,
    Little
}


/// Supported architectures
pub trait Architecture: Debug + Send + Sync {
    fn endian(&self) -> Endian;
    fn translator(&self) -> Box<translator::Translator>;
    fn calling_convention(&self) -> CallingConvention;
    fn stack_pointer(&self) -> il::Scalar;
    fn word_size(&self) -> usize;
}


#[derive(Clone, Debug, Eq, PartialEq)]
pub struct X86 {}

impl X86 {
    pub fn new() -> X86 { X86 {} }
}

impl Architecture for X86 {
    fn endian(&self) -> Endian { Endian::Little }
    fn translator(&self) -> Box<translator::Translator> {
        Box::new(translator::x86::X86::new())
    }
    fn calling_convention(&self) -> CallingConvention {
        CallingConvention::new(CallingConventionType::Cdecl)
    }
    fn stack_pointer(&self) -> il::Scalar { il::scalar("esp", 32) }
    fn word_size(&self) -> usize { 32 }
}


#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Mips {}

impl Mips {
    pub fn new() -> Mips { Mips {} }
}

impl Architecture for Mips {
    fn endian(&self) -> Endian { Endian::Big }
    fn translator(&self) -> Box<translator::Translator> {
        Box::new(translator::mips::Mips::new())
    }
    fn calling_convention(&self) -> CallingConvention {
        CallingConvention::new(CallingConventionType::MipsSystemV)
    }
    fn stack_pointer(&self) -> il::Scalar { il::scalar("$sp", 32) }
    fn word_size(&self) -> usize { 32 }
}


#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Mipsel {}

impl Mipsel {
    pub fn new() -> Mipsel { Mipsel {} }
}

impl Architecture for Mipsel {
    fn endian(&self) -> Endian { Endian::Big }
    fn translator(&self) -> Box<translator::Translator> {
        Box::new(translator::mips::Mipsel::new())
    }
    fn calling_convention(&self) -> CallingConvention {
        CallingConvention::new(CallingConventionType::MipsSystemV)
    }
    fn stack_pointer(&self) -> il::Scalar { il::scalar("$sp", 32) }
    fn word_size(&self) -> usize { 32 }
}