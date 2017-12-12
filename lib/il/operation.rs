//! An `Operation` applies semantics to `Array` and `Scalar` with `Expression`, or emits
//! `Raise`.

use std::fmt;
use il::*;

/// An IL Operation updates some state.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub enum Operation {
    /// Assign the value given in expression to the variable indicated.
    Assign {
        dst: Scalar,
        src: Expression
    },
    /// Store the value in src at the address given in index.
    Store {
        index: Expression,
        src: Expression
    },
    /// Load the value in memory at index and place the result in the variable dst.
    Load {
        dst: Scalar,
        index: Expression,
    },
    /// Branch to the value given by target.
    Branch {
        target: Expression
    },
    /// Raise operation for handling things such as system calls.
    Raise {
        expr: Expression,
    }
}


impl Operation {
    /// Create a new `Operation::Assign`.
    pub fn assign(dst: Scalar, src: Expression) -> Operation {
        Operation::Assign {
            dst: dst,
            src: src
        }
    }

    /// Create a new `Operation::Store`.
    pub fn store(index: Expression, src: Expression) -> Operation {
        Operation::Store { index: index, src: src }
    }

    /// Create a new `Operation::Load`.
    pub fn load(dst: Scalar, index: Expression) -> Operation {
        Operation::Load { dst: dst, index: index }
    }

    /// Create a new `Operation::Brc`.
    pub fn branch(target: Expression) -> Operation {
        Operation::Branch { target: target }
    }

    /// Create a new `Operation::Raise`.
    pub fn raise(expr: Expression) -> Operation {
        Operation::Raise { expr: expr }
    }

    /// Get each `Scalar` read by this `Operation`.
    pub fn scalars_read(&self) -> Vec<&Scalar> {
        let mut read: Vec<&Scalar> = Vec::new();
        match *self {
            Operation::Assign { ref src, .. } => {
                read.append(&mut src.scalars());
            },
            Operation::Store { ref index, ref src } => {
                read.append(&mut index.scalars());
                read.append(&mut src.scalars());
            },
            Operation::Load { ref index, .. } => {
                read.append(&mut index.scalars());
            },
            Operation::Branch { ref target } => {
                read.append(&mut target.scalars());
            },
            Operation::Raise { ref expr } => {
                read.append(&mut expr.scalars());
            }
        }
        read
    }

    /// Get a mutable reference to each `Scalar` read by this `Operation`.
    pub fn scalars_read_mut(&mut self) -> Vec<&mut Scalar> {
        let mut read: Vec<&mut Scalar> = Vec::new();
        match *self {
            Operation::Assign { ref mut src, .. } => {
                read.append(&mut src.scalars_mut());
            },
            Operation::Store { ref mut index, ref mut src } => {
                read.append(&mut index.scalars_mut());
                read.append(&mut src.scalars_mut());
            },
            Operation::Load { ref mut index, .. } => {
                read.append(&mut index.scalars_mut());
            },
            Operation::Branch { ref mut target } => {
                read.append(&mut target.scalars_mut());
            },
            Operation::Raise { ref mut expr } => {
                read.append(&mut expr.scalars_mut());
            }
        }

        read
    }

    /// Get a reference to the `Scalar` written by this `Operation`, or `None`
    /// if no `Scalar` is written.
    pub fn scalar_written(&self) -> Option<&Scalar> {
        match *self {
            Operation::Assign { ref dst, .. } |
            Operation::Load   { ref dst, .. } => Some(dst),
            Operation::Store  { .. } |
            Operation::Branch { .. } |
            Operation::Raise  { .. } => None
        }
    }

    /// Get a mutable reference to the `Scalar` written by this `Operation`, or `None`,
    /// if no `Scalar` is written.
    pub fn scalar_written_mut(&mut self) -> Option<&mut Scalar> {
        match *self {
            Operation::Assign { ref mut dst, .. } |
            Operation::Load   { ref mut dst, .. } => Some(dst),
            Operation::Store  { .. } |
            Operation::Branch { .. } |
            Operation::Raise  { .. } => None
        }
    }
}


impl fmt::Display for Operation {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Operation::Assign { ref dst, ref src } =>
                write!(f, "{} = {}", dst, src),
            Operation::Store { ref index, ref src } =>
                write!(f, "[{}] = {}", index, src),
            Operation::Load { ref dst, ref index } =>
                write!(f, "{} = [{}]", dst, index),
            Operation::Branch { ref target } =>
                write!(f, "branch {}", target),
            Operation::Raise { ref expr } => 
                write!(f, "raise {}", expr)
        }
    }
}