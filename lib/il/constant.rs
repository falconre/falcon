//! A `Constant` holds a single value.
//!
//! Currently, only constant values upto 64-bits are supported.

use std::fmt;
use il::*;


/// A constant value for Falcon IL
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct Constant {
    value: u64,
    bits: usize
}


impl Constant {
    /// Create a new `Constant` with the given value and bitness.
    pub fn new(value: u64, bits: usize) -> Constant {
        Constant { value: value, bits: bits }
    }

    /// Get the value of this `Constant`.
    pub fn value(&self) -> u64 {
        if self.bits == 64 {
            self.value
        }
        else {
            self.value & ((1 << self.bits) - 1)
        }
    }

    /// Get the number of bits for this `Constant`.
    pub fn bits(&self) -> usize {
        self.bits
    }
}


impl fmt::Display for Constant {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "0x{:X}:{}", self.value(), self.bits)
    }
}


impl Into<Expression> for Constant {
    fn into(self) -> Expression {
        Expression::constant(self)
    }
}