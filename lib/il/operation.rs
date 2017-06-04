use std::cell::RefCell;
use std::fmt;
use std::ops::Deref;
use il::*;

/// An IL Operation updates some state.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
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
    /// Phi operation for SSA
    Phi {
        dst: MultiVar,
        src: Vec<MultiVar>
    },
    /// Raise operation for handling things such as system calls
    Raise {
        expr: Expression,
    }
}


impl Operation {
    pub fn assign(dst: Scalar, src: Expression) -> Operation {
        Operation::Assign {
            dst: dst,
            src: src
        }
    }

    pub fn store(dst: Array, index: Expression, src: Expression) -> Operation {
        Operation::Store { dst: dst, index: index, src: src }
    }

    pub fn load(dst: Scalar, index: Expression, src: Array) -> Operation {
        Operation::Load { dst: dst, index: index, src: src }
    }

    pub fn brc(target: Expression, condition: Expression) -> Operation {
        Operation::Brc { target: target, condition: condition }
    }

    pub fn phi(dst: MultiVar, src: Vec<MultiVar>) -> Operation {
        Operation::Phi { dst: dst, src: src }
    }

    pub fn raise(expr: Expression) -> Operation {
        Operation::Raise { expr: expr }
    }

    pub fn variables_read<V>(&self) -> Vec<&V> where V: Variable {
        fn collect_scalars<V: Variable>(expr: &Expression) -> Vec<&V> {
            expr.collect_scalars()
                .iter()
                .map(|s| *s as &V)
                .collect::<Vec<&V>>()
        }
        let mut read: Vec<&V> = Vec::new();
        match *self {
            Operation::Assign { dst: _, ref src } => {
                read.append(&mut collect_scalars(src));
            },
            Operation::Store { dst: _, ref index, ref src } => {
                read.append(&mut collect_scalars(index));
                read.append(&mut collect_scalars(src));
            },
            Operation::Load { dst: _, ref index, ref src } => {
                read.append(&mut collect_scalars(index));
                read.push(src);
            },
            Operation::Brc { ref target, ref condition } => {
                read.append(&mut collect_scalars(target));
                read.append(&mut collect_scalars(condition));
            },
            Operation::Phi { dst: _, ref src } => {
                for multi_var in src {
                    read.push(multi_var as &V);
                }
            },
            Operation::Raise { ref expr } => {
                read.append(&mut collect_scalars(expr));
            }
        }
        read
    }

    pub fn variable_written<V>(&self) -> Option<&V> where V: Variable {
        match *self {
            Operation::Assign { ref dst, src: _ } => Some(dst),
            Operation::Store { ref dst, index: _, src: _ } => Some(dst),
            Operation::Load { ref dst, index: _ , src:_ } => Some(dst),
            Operation::Brc { target: _, condition: _ } => None,
            Operation::Phi { ref dst, src: _ } => Some(dst),
            Operation::Raise { expr: _ } => None
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
            Operation::Phi { ref dst, ref src } => 
                write!(f, "phi {} <- {{{}}}", dst,
                    src.iter()
                       .map(|v| format!("{}", v))
                       .collect::<Vec<String>>()
                       .join(", ")),
            Operation::Raise { ref expr } => 
                write!(f, "raise({})", expr)
        }
    }
}