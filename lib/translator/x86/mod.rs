//! Capstone-based translator for 32/64-bit x86.

use error::*;
use translator::{Translator, BlockTranslationResult};

mod mode;
mod semantics;
mod translator;
mod x86register;

use self::mode::Mode;

/// The X86 translator.
#[derive(Clone, Debug)]
pub struct X86;


impl X86 {
    pub fn new() -> X86 {
        X86
    }
}

impl Translator for X86 {
    fn translate_block(&self, bytes: &[u8], address: u64)
        -> Result<BlockTranslationResult> {

        translator::translate_block(Mode::X86, bytes, address)
    }
}



/// The Amd64 translator.
#[derive(Clone, Debug)]
pub struct Amd64;

impl Amd64 {
    pub fn new() -> Amd64 {
        Amd64
    }
}

impl Translator for Amd64 {
    fn translate_block(&self, bytes: &[u8], address: u64)
        -> Result<BlockTranslationResult> {

        translator::translate_block(Mode::Amd64, bytes, address)
    }
}