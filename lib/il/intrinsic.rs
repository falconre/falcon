//! Intrinsics are instructions Falcon cannot model.

use crate::il::*;
use serde::{Deserialize, Serialize};
use std::fmt;

/// An Instrinsic is a lifted instruction Falcon cannot model.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct Intrinsic {
    mnemonic: String,
    instruction_str: String,
    arguments: Vec<Expression>,
    written_expressions: Option<Vec<Expression>>,
    read_expressions: Option<Vec<Expression>>,
    bytes: Vec<u8>,
}

impl Intrinsic {
    /// Create a new intrinsic instruction.
    pub fn new<S: Into<String>, SS: Into<String>>(
        mnemonic: S,
        instruction_str: SS,
        arguments: Vec<Expression>,
        written_expressions: Option<Vec<Expression>>,
        read_expressions: Option<Vec<Expression>>,
        bytes: Vec<u8>,
    ) -> Intrinsic {
        Intrinsic {
            mnemonic: mnemonic.into(),
            instruction_str: instruction_str.into(),
            arguments,
            written_expressions,
            read_expressions,
            bytes,
        }
    }

    /// Get the mnemonic for the instruction this intrinsic represents.
    pub fn mnemonic(&self) -> &str {
        &self.mnemonic
    }

    /// Get the full disassembly string, mnemonic and operands, for the
    /// instruction this intrinsic represents.
    pub fn instruction_str(&self) -> &str {
        &self.instruction_str
    }

    /// Get the arguments for the intrinsic. Intrinsic-dependent.
    pub fn arguments(&self) -> &[Expression] {
        &self.arguments
    }

    /// Get the expressions which are written by this intrinsic.
    ///
    /// If this is None, the expressions written by this intrinsic are
    /// undefined, and for soundness you should assume the intrinsic does
    /// anything.
    pub fn written_expressions(&self) -> Option<&[Expression]> {
        self.written_expressions.as_deref()
    }

    /// Get a mutable reference to the expressions which are written by this
    /// intrinsic.
    ///
    /// Caveats for `written_expressions` apply here.
    pub fn written_expressions_mut(&mut self) -> Option<&mut [Expression]> {
        self.written_expressions.as_deref_mut()
    }

    /// Get the expressions which are read by this intrinsic.
    ///
    /// If this is None, the expressions read by this intrinsic are
    /// undefined, and for soundness you should assume the intrinsic reads
    /// any expression.
    pub fn read_expressions(&self) -> Option<&[Expression]> {
        self.read_expressions.as_deref()
    }

    /// Get a mutable reference to the expressions which are read by this
    /// intrinsic.
    ///
    /// Caveats for `read_expressions` apply here.
    pub fn read_expressions_mut(&mut self) -> Option<&mut [Expression]> {
        self.read_expressions.as_deref_mut()
    }

    /// Get the scalars which are written by this intrinsic.
    ///
    /// These are the scalars contained in the written expressions. Caveats for
    /// `written_expressions` apply here.
    pub fn scalars_written(&self) -> Option<Vec<&Scalar>> {
        self.written_expressions().map(|written_expressions| {
            written_expressions
                .iter()
                .flat_map(|expression| expression.scalars())
                .collect::<Vec<&Scalar>>()
        })
    }

    /// Get a mutable reference to the scalars written by this intrinsic.
    ///
    /// This is a mutable reference to the scalars contained in the written
    /// expressions. Caveats for `written_expressions` apply here.
    pub fn scalars_written_mut(&mut self) -> Option<Vec<&mut Scalar>> {
        self.written_expressions_mut().map(|written_expressions| {
            written_expressions
                .iter_mut()
                .flat_map(|expression| expression.scalars_mut())
                .collect::<Vec<&mut Scalar>>()
        })
    }

    /// Get the scalared read by this intrinsic.
    ///
    /// These are the scalars in the expressions read by this intrinsic.
    /// Caveats for `read_expressions` apply here.
    pub fn scalars_read(&self) -> Option<Vec<&Scalar>> {
        self.read_expressions().map(|read_expressions| {
            read_expressions
                .iter()
                .flat_map(|expression| expression.scalars())
                .collect::<Vec<&Scalar>>()
        })
    }

    /// Get a mutable reference to the scalars written by this inrinsic.
    ///
    /// These are the scalars in the expression written by this intrinsic.
    /// Caveats for `read_expressions` apply here.
    pub fn scalars_read_mut(&mut self) -> Option<Vec<&mut Scalar>> {
        self.read_expressions_mut().map(|read_expressions| {
            read_expressions
                .iter_mut()
                .flat_map(|expression| expression.scalars_mut())
                .collect::<Vec<&mut Scalar>>()
        })
    }

    /// Get the bytes which make up this instruction.
    ///
    /// These are the undisassembled bytes, as found in the lifted binary.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl fmt::Display for Intrinsic {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let bytes = self
            .bytes()
            .iter()
            .map(|byte| format!("{:02x}", byte))
            .collect::<Vec<String>>()
            .join("");
        write!(f, "{} {}", bytes, self.instruction_str())
    }
}
