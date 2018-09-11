//! Information and types for Falcon's supported architectures.

use analysis::calling_convention::{CallingConvention, CallingConventionType};
use il;
use std::fmt::Debug;
use translator;



/// An architecture's endanness.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum Endian {
    Big,
    Little
}


/// Necessary functions for analysis over architectures.
pub trait Architecture: Debug + Send + Sync {
    /// Get the name of this architecture
    fn name(&self) -> &str;
    /// Get the endianness of this architecture.
    fn endian(&self) -> Endian;
    /// Get this architecture's translator.
    fn translator(&self) -> Box<translator::Translator>;
    /// Get the _default_ calling convention for this architecture.
    fn calling_convention(&self) -> CallingConvention;
    /// Get the scalar used to represent the stack pointer by this
    /// architecture's translator.
    fn stack_pointer(&self) -> il::Scalar;
    /// Get the size of a natural word for this architecture in bits.
    fn word_size(&self) -> usize;
    /// Clone into a boxed `Architecture`
    fn box_clone(&self) -> Box<Architecture>;
}


/// The 64-bit X86 Architecture.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Amd64 {}

impl Amd64 {
    pub fn new() -> Amd64 { Amd64 {} }
}

impl Architecture for Amd64 {
    fn name(&self) -> &str { &"amd64" }
    fn endian(&self) -> Endian { Endian::Little }
    fn translator(&self) -> Box<translator::Translator> {
        Box::new(translator::x86::Amd64::new())
    }
    fn calling_convention(&self) -> CallingConvention {
        CallingConvention::new(CallingConventionType::Amd64SystemV)
    }
    fn stack_pointer(&self) -> il::Scalar { il::scalar("rsp", 64) }
    fn word_size(&self) -> usize { 64 }
    fn box_clone(&self) -> Box<Architecture> { Box::new(self.clone()) }
}


/// The 32-bit Mips Architecture.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Mips {}

impl Mips {
    pub fn new() -> Mips { Mips {} }
}

impl Architecture for Mips {
    fn name(&self) -> &str { &"mips" }
    fn endian(&self) -> Endian { Endian::Big }
    fn translator(&self) -> Box<translator::Translator> {
        Box::new(translator::mips::Mips::new())
    }
    fn calling_convention(&self) -> CallingConvention {
        CallingConvention::new(CallingConventionType::MipsSystemV)
    }
    fn stack_pointer(&self) -> il::Scalar { il::scalar("$sp", 32) }
    fn word_size(&self) -> usize { 32 }
    fn box_clone(&self) -> Box<Architecture> { Box::new(self.clone()) }
}


/// The 32-bit Mipsel Architecture.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Mipsel {}

impl Mipsel {
    pub fn new() -> Mipsel { Mipsel {} }
}

impl Architecture for Mipsel {
    fn name(&self) -> &str { &"mipsel" }
    fn endian(&self) -> Endian { Endian::Big }
    fn translator(&self) -> Box<translator::Translator> {
        Box::new(translator::mips::Mipsel::new())
    }
    fn calling_convention(&self) -> CallingConvention {
        CallingConvention::new(CallingConventionType::MipsSystemV)
    }
    fn stack_pointer(&self) -> il::Scalar { il::scalar("$sp", 32) }
    fn word_size(&self) -> usize { 32 }
    fn box_clone(&self) -> Box<Architecture> { Box::new(self.clone()) }
}


/// The 32-bit X86 Architecture.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct X86 {}

impl X86 {
    pub fn new() -> X86 { X86 {} }
}

impl Architecture for X86 {
    fn name(&self) -> &str { &"x86" }
    fn endian(&self) -> Endian { Endian::Little }
    fn translator(&self) -> Box<translator::Translator> {
        Box::new(translator::x86::X86::new())
    }
    fn calling_convention(&self) -> CallingConvention {
        CallingConvention::new(CallingConventionType::Cdecl)
    }
    fn stack_pointer(&self) -> il::Scalar { il::scalar("esp", 32) }
    fn word_size(&self) -> usize { 32 }
    fn box_clone(&self) -> Box<Architecture> { Box::new(self.clone()) }
}