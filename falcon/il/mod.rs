//! Falcon Intermediate Language

use std::rc::Rc;

use error::*;
use graph;

pub mod block;
pub mod constant;
pub mod control_flow_graph;
pub mod expression;
pub mod function;
pub mod instruction;
pub mod operation;
pub mod program;
pub mod variable;

pub use self::block::*;
pub use self::constant::*;
pub use self::control_flow_graph::*;
pub use self::expression::*;
pub use self::function::*;
pub use self::instruction::*;
pub use self::operation::*;
pub use self::program::*;
pub use self::variable::*;

/// A convenience function to createa a new expression constant.
pub fn expr_const(value: u64, bits: usize) -> Expression {
    Expression::constant(Constant::new(value, bits))
}


/// A convenience function to create a new expression variable.
pub fn expr_var<S>(name: S, bits: usize) -> Expression where S: Into<String> {
    Expression::variable(Variable::new(name, bits))
}


/// A convenience function to create a new variable.
pub fn var<S>(name: S, bits: usize) -> Variable where S: Into<String> {
    Variable::new(name, bits)
}




