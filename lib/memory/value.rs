//! A value used in the paged memory model.

use error::*;
use executor::eval;
use il;
use std::fmt::Debug;


/// In order for a value to be used in the paged memory model, it must implement
/// this trait.
pub trait Value: Clone + Debug + Eq + PartialEq {
    /// Turn an il::Constant into a representation of this Value
    fn constant(constant: il::Constant) -> Self;

    /// Return the number of bits contained in this value
    fn bits(&self) -> usize;

    /// Shift the value left by the given number of bits
    fn shl(&self, bits: usize) -> Result<Self>;

    /// Shift the value right by the given number of bits
    fn shr(&self, bits: usize) -> Result<Self>;

    /// Truncate the value to the given number of bits
    fn trun(&self, bits: usize) -> Result<Self>;

    /// Zero-extend the value to the given number of bits
    fn zext(&self, bits: usize) -> Result<Self>;

    /// Or this value with the given value
    fn or(&self, other: &Self) -> Result<Self>;
}


impl Value for il::Constant {
    fn constant(constant: il::Constant) -> Self {
        constant
    }

    fn bits(&self) -> usize {
        self.bits()
    }

    fn shl(&self, bits: usize) -> Result<Self> {
        eval(&il::Expression::shl(self.clone().into(), il::expr_const(bits as u64, self.bits()))?)
    }

    fn shr(&self, bits: usize) -> Result<Self> {
        eval(&il::Expression::shr(self.clone().into(), il::expr_const(bits as u64, self.bits()))?)
    }

    fn trun(&self, bits: usize) -> Result<Self> {
        eval(&il::Expression::trun(bits, self.clone().into())?)
    }

    fn zext(&self, bits: usize) -> Result<Self> {
        eval(&il::Expression::zext(bits, self.clone().into())?)
    }

    fn or(&self, other: &Self) -> Result<Self> {
        eval(&il::Expression::or(self.clone().into(), other.clone().into())?)
    }
}