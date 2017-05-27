use std::fmt;
use il::*;

/// An IL Operation updates some state.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub enum Operation {
    /// Assign the value given in expression to the variable indicated.
    Assign {
        dst: Variable,
        src: Expression
    },
    /// Store the value given by expression at the address given.
    Store {
        address: Expression,
        src: Expression
    },
    /// Load the value given by address and place the result in the variable dst.
    Load {
        dst: Variable,
        address: Expression
    },
    /// If condition is non-zero, branch to the value given by dst.
    Brc {
        dst: Expression,
        condition: Expression
    },
    /// Phi operation for SSA
    Phi {
        dst: Variable,
        src: Vec<Variable>
    },
    /// Raise operation for handling things such as system calls
    Raise {
        expr: Expression,
    }
}


impl Operation {
    pub fn assign(dst: Variable, src: Expression) -> Operation {
        Operation::Assign { dst: dst, src: src }
    }

    pub fn store(address: Expression, src: Expression) -> Operation {
        Operation::Store { address: address, src: src }
    }

    pub fn load(dst: Variable, address: Expression) -> Operation {
        Operation::Load { dst: dst, address: address }
    }

    pub fn brc(dst: Expression, condition: Expression) -> Operation {
        Operation::Brc { dst: dst, condition: condition }
    }

    pub fn phi(dst: Variable, src: Vec<Variable>) -> Operation {
        Operation::Phi { dst: dst, src: src }
    }

    pub fn raise(expr: Expression) -> Operation {
        Operation::Raise { expr: expr }
    }

    pub fn variables_read(&self) -> Vec<&Variable> {
        let mut read = Vec::new();
        match *self {
            Operation::Assign { ref dst, ref src } => {
                read.append(&mut src.collect_variables());
            },
            Operation::Store { ref address, ref src } => {
                read.append(&mut address.collect_variables());
                read.append(&mut src.collect_variables());
            },
            Operation::Load { ref dst, ref address } => {
                read.append(&mut address.collect_variables());
            },
            Operation::Brc { ref dst, ref condition } => {
                read.append(&mut dst.collect_variables());
                read.append(&mut condition.collect_variables());
            },
            Operation::Phi { ref dst, ref src } => {
                for variable in src {
                    read.push(variable);
                }
            },
            Operation::Raise { ref expr } => {
                read.append(&mut expr.collect_variables());
            }
        }
        read
    }

    pub fn variables_read_mut(&mut self) -> Vec<&mut Variable> {
        let mut read: Vec<&mut Variable> = Vec::new();
        match *self {
            Operation::Assign { ref mut dst, ref mut src } => {
                read.append(&mut src.collect_variables_mut());
            },
            Operation::Store { ref mut address, ref mut src } => {
                read.append(&mut address.collect_variables_mut());
                read.append(&mut src.collect_variables_mut());
            },
            Operation::Load { ref mut dst, ref mut address } => {
                read.append(&mut address.collect_variables_mut());
            },
            Operation::Brc { ref mut dst, ref mut condition } => {
                read.append(&mut dst.collect_variables_mut());
                read.append(&mut condition.collect_variables_mut());
            },
            Operation::Phi { ref mut dst, ref mut src } => {
                for variable in src {
                    read.push(variable);
                }
            },
            Operation::Raise { ref mut expr } => {
                read.append(&mut expr.collect_variables_mut());
            }
        }
        read
    }

    pub fn variable_written(&self) -> Option<&Variable> {
        match *self {
            Operation::Assign { ref dst, src: _ } => Some(dst),
            Operation::Store { address: _, src: _ } => None,
            Operation::Load { ref dst, address: _ } => Some(dst),
            Operation::Brc { dst: _, condition: _ } => None,
            Operation::Phi { ref dst, src: _ } => Some(dst),
            Operation::Raise { expr: _ } => None
        }
    }

    pub fn variable_written_mut(&mut self) -> Option<&mut Variable> {
        match *self {
            Operation::Assign { ref mut dst, src: _ } => Some(dst),
            Operation::Store { address: _, src: _ } => None,
            Operation::Load { ref mut dst, address: _ } => Some(dst),
            Operation::Brc { dst: _, condition: _ } => None,
            Operation::Phi { ref mut dst, src: _ } => Some(dst),
            Operation::Raise { expr: _ } => None
        }
    }
}


impl fmt::Display for Operation {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Operation::Assign { ref dst, ref src } =>
                write!(f, "{} = {}", dst, src),
            Operation::Store { ref address, ref src } =>
                write!(f, "[{}] = {}", address, src),
            Operation::Load { ref dst, ref address } =>
                write!(f, "{} = [{}]", dst, address),
            Operation::Brc { ref dst, ref condition } =>
                write!(f, "brc {} ? {}", dst, condition),
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