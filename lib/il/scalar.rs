//! A `Scalar` is a variable which holds a single value.

use serde::{Deserialize, Serialize};
use std::fmt;

/// A `Scalar` is a variable which holds a single value.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct Scalar {
    name: String,
    bits: usize,
    ssa: Option<usize>,
}

/// A scalar value for Falcon IL.
impl Scalar {
    /// Create a new `Scalar` with the given name and bitness.
    pub fn new<S>(name: S, bits: usize) -> Scalar
    where
        S: Into<String>,
    {
        Scalar {
            name: name.into(),
            bits,
            ssa: None,
        }
    }

    /// Create a temporary `Scalar` with the given index and bitness.
    pub fn temp(index: u64, bits: usize) -> Self {
        Self::new(format!("temp_0x{:X}", index), bits)
    }

    /// Gets the bitness of the `Scalar`.
    pub fn bits(&self) -> usize {
        self.bits
    }

    /// Gets the name of the `Scalar`.
    pub fn name(&self) -> &str {
        &self.name
    }

    // Gets the SSA version of the `Scalar` or None if no SSA version is set.
    pub fn ssa(&self) -> Option<usize> {
        self.ssa
    }

    // Sets the SSA version of the `Scalar`.
    pub fn set_ssa(&mut self, ssa: Option<usize>) {
        self.ssa = ssa;
    }

    /// An identifier for the `Scalar`. This is the string which is displayed
    /// when printing the IL.
    pub fn identifier(&self) -> String {
        let ssa = match self.ssa() {
            Some(ssa) => format!(".{}", ssa),
            None => String::default(),
        };

        format!("{}{}:{}", self.name, ssa, self.bits)
    }
}

impl fmt::Display for Scalar {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.identifier())
    }
}
