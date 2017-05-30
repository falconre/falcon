use std::cell::RefCell;
use std::fmt;
use std::ops::Deref;
use il::*;

/// An IL Operation updates some state.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub enum Operation {
    /// Assign the value given in expression to the variable indicated.
    Assign {
        dst: Rc<RefCell<Scalar>>,
        src: Expression
    },
    /// Store the value given by expression at the address given.
    Store {
        dst: Rc<RefCell<Array>>,
        index: Expression,
        src: Expression
    },
    /// Load the value given by address and place the result in the variable dst.
    Load {
        dst: Rc<RefCell<Scalar>>,
        index: Expression,
        src: Rc<RefCell<Array>>
    },
    /// If condition is non-zero, branch to the value given by dst.
    Brc {
        target: Expression,
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
    pub fn assign(dst: Scalar, src: Expression) -> Operation {
        Operation::Assign {
            dst: Rc::new(RefCell::new(dst)),
            src: src
        }
    }

    pub fn store(dst: Array, index: Expression, src: Expression) -> Operation {
        Operation::Store {
            dst: Rc::new(RefCell::new(dst)),
            index: index,
            src: src
        }
    }

    pub fn load(dst: Scalar, index: Expression, src: Array) -> Operation {
        Operation::Load {
            dst: Rc::new(RefCell::new(dst)),
            index: index,
            src: Rc::new(RefCell::new(src))
        }
    }

    pub fn brc(target: Expression, condition: Expression) -> Operation {
        Operation::Brc { target: target, condition: condition }
    }

    pub fn phi(dst: Variable, src: Vec<Variable>) -> Operation {
        Operation::Phi { dst: dst, src: src }
    }

    pub fn raise(expr: Expression) -> Operation {
        Operation::Raise { expr: expr }
    }

    pub fn variables_read(&self) -> Vec<Variable> {

        fn collect_scalars(expr: &Expression) -> Vec<Variable> {
            expr.collect_scalars()
                .iter()
                .map(|s| Variable::scalar(s.clone()))
                .collect::<Vec<Variable>>()
        }

        let mut read: Vec<Variable> = Vec::new();
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
                read.push(Variable::array(src.clone()));
            },
            Operation::Brc { ref target, ref condition } => {
                read.append(&mut collect_scalars(target));
                read.append(&mut collect_scalars(condition));
            },
            Operation::Phi { dst: _, ref src } => {
                for variable in src {
                    read.push(variable.clone());
                }
            },
            Operation::Raise { ref expr } => {
                read.append(&mut collect_scalars(expr));
            }
        }
        read
    }

    pub fn variable_written(&self) -> Option<Variable> {
        match *self {
            Operation::Assign { ref dst, src: _ } =>
                Some(Variable::scalar(dst.clone())),
            Operation::Store { ref dst, index: _, src: _ } =>
                Some(Variable::array(dst.clone())),
            Operation::Load { ref dst, index: _ , src:_ } =>
                Some(Variable::scalar(dst.clone())),
            Operation::Brc { target: _, condition: _ } => None,
            Operation::Phi { ref dst, src: _ } => Some(dst.clone()),
            Operation::Raise { expr: _ } => None
        }
    }
}


impl fmt::Display for Operation {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Operation::Assign { ref dst, ref src } =>
                write!(f, "{} = {}", dst.borrow().deref(), src),
            Operation::Store { ref dst, ref index, ref src } =>
                write!(f, "{}[{}] = {}", dst.borrow().deref(), index, src),
            Operation::Load { ref dst, ref index, ref src } =>
                write!(f, "{} = {}[{}]", dst.borrow().deref(), src.borrow().deref(), index),
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