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
    /// Store the value given by expression at the address given.
    Store {
        dst: Array,
        index: Expression,
        src: Expression
    },
    /// Load the value given by address and place the result in the variable dst.
    Load {
        dst: Scalar,
        index: Expression,
        src: Array
    },
    /// If condition is non-zero, branch to the value given by dst.
    Brc {
        target: Expression,
        condition: Expression
    },
    /// Raise operation for handling things such as system calls
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
    pub fn store(dst: Array, index: Expression, src: Expression) -> Operation {
        Operation::Store { dst: dst, index: index, src: src }
    }

    /// Create a new `Operation::Load`.
    pub fn load(dst: Scalar, index: Expression, src: Array) -> Operation {
        Operation::Load { dst: dst, index: index, src: src }
    }

    /// Create a new `Operation::Brc`.
    pub fn brc(target: Expression, condition: Expression) -> Operation {
        Operation::Brc { target: target, condition: condition }
    }

    /// Create a new `Operation::Raise`.
    pub fn raise(expr: Expression) -> Operation {
        Operation::Raise { expr: expr }
    }

    /// Get eacn `Variable` read by this `Operation`.
    pub fn variables_read(&self) -> Vec<&Variable> {
        fn scalars(expr: &Expression) -> Vec<&Variable> {
            expr.scalars()
                .iter()
                .map(|s| *s as &Variable)
                .collect::<Vec<&Variable>>()
        }
        let mut read: Vec<&Variable> = Vec::new();
        match *self {
            Operation::Assign { ref src, .. } => {
                read.append(&mut scalars(src));
            },
            Operation::Store { ref index, ref src, .. } => {
                read.append(&mut scalars(index));
                read.append(&mut scalars(src));
            },
            Operation::Load { ref index, ref src, .. } => {
                read.append(&mut scalars(index));
                read.push(src);
            },
            Operation::Brc { ref target, ref condition } => {
                read.append(&mut scalars(target));
                read.append(&mut scalars(condition));
            },
            Operation::Raise { ref expr } => {
                read.append(&mut scalars(expr));
            }
        }
        read
    }

    /// Get a mutable reference to each `Variable` read by this `Operation`.
    pub fn variables_read_mut(&mut self) -> Vec<&mut Variable> {
        fn scalars_mut(expr: &mut Expression) -> Vec<&mut Variable> {
            let mut v: Vec<&mut Variable> = Vec::new();
            for s in expr.scalars_mut() {
                v.push(s)
            }
            v
        }

        let mut read: Vec<&mut Variable> = Vec::new();

        match *self {
            Operation::Assign { ref mut src, .. } => {
                read.append(&mut scalars_mut(src));
            },
            Operation::Store { ref mut index, ref mut src, .. } => {
                read.append(&mut scalars_mut(index));
                read.append(&mut scalars_mut(src));
            },
            Operation::Load { ref mut index, ref mut src, .. } => {
                read.append(&mut scalars_mut(index));
                read.push(src);
            },
            Operation::Brc { ref mut target, ref mut condition } => {
                read.append(&mut scalars_mut(target));
                read.append(&mut scalars_mut(condition));
            },
            Operation::Raise { ref mut expr } => {
                read.append(&mut scalars_mut(expr));
            }
        }

        read
    }

    /// Get a reference to the `Variable` written by this `Operation`, or `None`
    /// if no `Variable` is written.
    pub fn variable_written(&self) -> Option<&Variable> {
        match *self {
            Operation::Assign { ref dst, .. } |
            Operation::Load   { ref dst, .. } => Some(dst),
            Operation::Store  { ref dst, .. } => Some(dst),
            Operation::Brc    { .. } |
            Operation::Raise  { .. } => None
        }
    }

    /// Get a mutable reference to the `Variable` written by this `Operation`, or `None`,
    /// if no `Variable` is written.
    pub fn variable_written_mut(&mut self) -> Option<&mut Variable> {
        match *self {
            Operation::Assign { ref mut dst, .. } |
            Operation::Load   { ref mut dst, .. } => Some(dst),
            Operation::Store  { ref mut dst, .. } => Some(dst),
            Operation::Brc    { .. } |
            Operation::Raise  { .. } => None
        }
    }
}


impl fmt::Display for Operation {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Operation::Assign { ref dst, ref src } =>
                write!(f, "{} = {}", dst, src),
            Operation::Store { ref dst, ref index, ref src } =>
                write!(f, "{}[{}] = {}", dst, index, src),
            Operation::Load { ref dst, ref index, ref src } =>
                write!(f, "{} = {}[{}]", dst, src, index),
            Operation::Brc { ref target, ref condition } =>
                write!(f, "brc {} ? {}", target, condition),
            Operation::Raise { ref expr } => 
                write!(f, "raise({})", expr)
        }
    }
}