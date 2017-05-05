use std::fmt;
use il::*;


/// An IL constant.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Constant {
    value: u64,
    bits: usize
}


impl Constant {
    pub fn new(value: u64, bits: usize) -> Constant {
        Constant { value: value, bits: bits }
    }

    pub fn value(&self) -> u64 {
        if self.bits == 64 {
            self.value
        }
        else {
            self.value & ((1 << self.bits) - 1)
        }
    }

    pub fn bits(&self) -> usize {
        self.bits
    }
}


impl fmt::Display for Constant {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "0x{:X}:{}", self.value, self.bits)
    }
}


impl Into<Expression> for Constant {
    fn into(self) -> Expression {
        Expression::constant(self)
    }
}