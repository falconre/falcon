//! Falcon Intermediate Language

use error::*;
use graph;

pub mod array;
pub mod block;
pub mod constant;
pub mod control_flow_graph;
pub mod expression;
pub mod function;
pub mod instruction;
pub mod operation;
pub mod scalar;
pub mod program;
pub mod variable;

pub use self::array::*;
pub use self::block::*;
pub use self::constant::*;
pub use self::control_flow_graph::*;
pub use self::expression::*;
pub use self::function::*;
pub use self::instruction::*;
pub use self::operation::*;
pub use self::scalar::*;
pub use self::program::*;
pub use self::variable::*;

/// A convenience function to create a new constant.
///
/// This is the preferred way to create a `Constant`.
pub fn const_(value: u64, bits: usize) -> Constant {
    Constant::new(value, bits)
}


/// A convenience function to create a new expression constant.
///
/// This is the preferred way to create an `Expression::Constant`.
pub fn expr_const(value: u64, bits: usize) -> Expression {
    Expression::constant(Constant::new(value, bits))
}


/// A convenience function to create a new scalar.
///
/// This is the preferred way to create a `Scalar`.
pub fn scalar<S>(name: S, bits: usize) -> Scalar where S: Into<String> {
    Scalar::new(name, bits)
}


/// A convenience function to create a new expression scalar.
///
/// This is the preferred way to create an `Expression::Scalar`.
pub fn expr_scalar<S>(name: S, bits: usize) -> Expression where S: Into<String> {
    Expression::scalar(Scalar::new(name, bits))
}


/// A convenience function to create a new array
///
/// This is the preferred way to create an `Array`.
pub fn array<S>(name: S, size: u64) -> Array where S: Into<String> {
    Array::new(name, size)
}