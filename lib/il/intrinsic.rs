//! Intrinsics are instructions we cannot model with Falcon.

use il::*;
use std::fmt;

/// An Instrinsic is a lifted instruction we cannot model.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct Intrinsic {
    mnemonic: String,
    instruction_str: String,
    written_expressions: Option<Vec<Expression>>,
    read_expressions: Option<Vec<Expression>>,
    bytes: Vec<u8>
}


impl Intrinsic {
    pub fn new<S: Into<String>, SS: Into<String>>(
        mnemonic: S,
        instruction_str: SS,
        written_expressions: Option<Vec<Expression>>,
        read_expressions: Option<Vec<Expression>>,
        bytes: Vec<u8>
    ) -> Intrinsic {
        Intrinsic {
            mnemonic: mnemonic.into(),
            instruction_str: instruction_str.into(),
            written_expressions: written_expressions,
            read_expressions: read_expressions,
            bytes: bytes.clone()
        }
    }

    pub fn mnemonic(&self) -> &str {
        &self.mnemonic
    }

    pub fn instruction_str(&self) -> &str {
        &self.instruction_str
    }

    pub fn written_expressions(&self) -> Option<&[Expression]> {
        self.written_expressions.as_ref().map(|x| x.as_slice())
    }

    pub fn written_expressions_mut(&mut self) -> Option<&mut [Expression]> {
        self.written_expressions.as_mut().map(|x| x.as_mut_slice())
    }

    pub fn read_expressions(&self) -> Option<&[Expression]> {
        self.read_expressions.as_ref().map(|x| x.as_slice())
    }

    pub fn read_expressions_mut(&mut self) -> Option<&mut [Expression]> {
        self.read_expressions.as_mut().map(|x| x.as_mut_slice())
    }

    pub fn scalars_written(&self) -> Vec<&Scalar> {
        self.written_expressions()
            .map(|written_expressions|
                written_expressions
                    .iter()
                    .flat_map(|expression| expression.scalars())
                    .collect::<Vec<&Scalar>>())
            .unwrap_or(Vec::new())
    }

    pub fn scalars_written_mut(&mut self) -> Vec<&mut Scalar> {
        self.written_expressions_mut()
            .map(|written_expressions|
                written_expressions
                    .iter_mut()
                    .flat_map(|expression| expression.scalars_mut())
                    .collect::<Vec<&mut Scalar>>())
            .unwrap_or(Vec::new())
    }

    pub fn scalars_read(&self) -> Vec<&Scalar> {
        self.read_expressions()
            .map(|read_expressions|
                read_expressions
                    .iter()
                    .flat_map(|expression| expression.scalars())
                    .collect::<Vec<&Scalar>>())
            .unwrap_or(Vec::new())
    }

    pub fn scalars_read_mut(&mut self) -> Vec<&mut Scalar> {
        self.read_expressions_mut()
            .map(|read_expressions|
                read_expressions
                    .iter_mut()
                    .flat_map(|expression| expression.scalars_mut())
                    .collect::<Vec<&mut Scalar>>())
            .unwrap_or(Vec::new())
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}


impl fmt::Display for Intrinsic {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let bytes = self.bytes()
            .into_iter()
            .map(|byte| format!("{:02x}", byte))
            .collect::<Vec<String>>()
            .join("");
        write!(f, "{} {}", bytes, self.instruction_str())
    }
}