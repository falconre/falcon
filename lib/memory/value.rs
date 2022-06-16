//! A value used in the paged memory model.

use crate::executor::eval;
use crate::il;
use crate::Error;
use std::fmt::Debug;

/// In order for a value to be used in the paged memory model, it must implement
/// this trait.
pub trait Value: Clone + Debug + Eq + PartialEq {
    /// Turn an il::Constant into a representation of this Value
    fn constant(constant: il::Constant) -> Self;

    /// Return the number of bits contained in this value
    fn bits(&self) -> usize;

    /// Shift the value left by the given number of bits
    fn shl(&self, bits: usize) -> Result<Self, Error>;

    /// Shift the value right by the given number of bits
    fn shr(&self, bits: usize) -> Result<Self, Error>;

    /// Truncate the value to the given number of bits
    fn trun(&self, bits: usize) -> Result<Self, Error>;

    /// Zero-extend the value to the given number of bits
    fn zext(&self, bits: usize) -> Result<Self, Error>;

    /// Or this value with the given value
    fn or(&self, other: &Self) -> Result<Self, Error>;
}

impl Value for il::Constant {
    fn constant(constant: il::Constant) -> Self {
        constant
    }

    fn bits(&self) -> usize {
        self.bits()
    }

    fn shl(&self, bits: usize) -> Result<Self, Error> {
        eval(&il::Expression::shl(
            self.clone().into(),
            il::expr_const(bits as u64, self.bits()),
        )?)
    }

    fn shr(&self, bits: usize) -> Result<Self, Error> {
        eval(&il::Expression::shr(
            self.clone().into(),
            il::expr_const(bits as u64, self.bits()),
        )?)
    }

    fn trun(&self, bits: usize) -> Result<Self, Error> {
        eval(&il::Expression::trun(bits, self.clone().into())?)
    }

    fn zext(&self, bits: usize) -> Result<Self, Error> {
        eval(&il::Expression::zext(bits, self.clone().into())?)
    }

    fn or(&self, other: &Self) -> Result<Self, Error> {
        eval(&il::Expression::or(
            self.clone().into(),
            other.clone().into(),
        )?)
    }
}

impl Value for il::Expression {
    fn constant(constant: il::Constant) -> Self {
        il::Expression::constant(constant)
    }

    fn bits(&self) -> usize {
        self.bits()
    }

    fn shl(&self, bits: usize) -> Result<Self, Error> {
        il::Expression::shl(self.clone(), il::expr_const(bits as u64, self.bits()))
    }

    fn shr(&self, bits: usize) -> Result<Self, Error> {
        il::Expression::shr(self.clone(), il::expr_const(bits as u64, self.bits()))
    }

    fn trun(&self, bits: usize) -> Result<Self, Error> {
        il::Expression::trun(bits, self.clone())
    }

    fn zext(&self, bits: usize) -> Result<Self, Error> {
        il::Expression::zext(bits, self.clone())
    }

    fn or(&self, other: &Self) -> Result<Self, Error> {
        il::Expression::or(self.clone(), other.clone())
    }
}
