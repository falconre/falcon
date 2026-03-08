//! Capstone-based translator for 32/64-bit x86.

use crate::translator::{BlockTranslationResult, Options, Translator};
use crate::Error;

mod mode;
mod semantics;
mod translator;
mod x86register;

#[cfg(test)]
mod test;

use self::mode::Mode;

/// The X86 translator.
#[derive(Clone, Debug, Default)]
pub struct X86;

impl X86 {
    pub fn new() -> X86 {
        X86
    }
}

impl Translator for X86 {
    fn translate_block(
        &self,
        bytes: &[u8],
        address: u64,
        options: &Options,
    ) -> Result<BlockTranslationResult, Error> {
        translator::translate_block(Mode::X86, bytes, address, options)
    }
}

/// The Amd64 translator.
#[derive(Clone, Debug, Default)]
pub struct Amd64;

impl Amd64 {
    pub fn new() -> Amd64 {
        Amd64
    }
}

impl Translator for Amd64 {
    fn translate_block(
        &self,
        bytes: &[u8],
        address: u64,
        options: &Options,
    ) -> Result<BlockTranslationResult, Error> {
        translator::translate_block(Mode::Amd64, bytes, address, options)
    }
}
