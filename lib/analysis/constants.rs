//! A very simple, and fast, constant propagation

use analysis::fixed_point;
use error::*;
use executor::eval;
use il;
use std::collections::{HashMap};
use std::cmp::{Ordering, PartialOrd};


/// Compute constants for the given function
pub fn constants<'r>(function: &'r il::Function)
-> Result<HashMap<il::RefProgramLocation<'r>, Constants>> {
    fixed_point::fixed_point_forward(ConstantsAnalysis{}, function)
}


#[derive(Clone, Debug, PartialEq)]
pub struct Constants {
    constants: HashMap<il::Scalar, il::Constant>
}


impl PartialOrd for Constants {
    fn partial_cmp(&self, other: &Constants) -> Option<Ordering> {

        if self.constants.len() < other.constants.len() {
            for (ls, lc) in self.constants.iter() {
                if !other.constants
                    .get(ls)
                    .map(|rc| rc >= lc)
                    .unwrap_or(false) {
                    return None;
                }
            }
            Some(Ordering::Less)
        }
        else if self.constants.len() > other.constants.len() {
            for (ls, lc) in other.constants.iter() {
                if !self.constants
                    .get(ls)
                    .map(|rc| rc >= lc)
                    .unwrap_or(false) {
                    return None;
                }
            }
            Some(Ordering::Less)
        }
        else if self.constants == other.constants {
            Some(Ordering::Equal)
        }
        else {
            None
        }
    }
}


impl Constants {
    pub fn new() -> Constants {
        Constants {
            constants: HashMap::new()
        }
    }

    pub fn scalar(&self, scalar: &il::Scalar) -> Option<&il::Constant> {
        self.constants.get(scalar)
    }

    pub fn set_scalar(&mut self, scalar: il::Scalar, constant: Option<il::Constant>) {
        if constant.is_none() {
            self.constants.remove(&scalar);
        }
        else {
            self.constants.insert(scalar, constant.unwrap());
        }
    }

    pub fn eval(&self, expression: &il::Expression) -> Option<il::Constant> {
        let expression_scalars = expression.scalars();

        let expression =
            expression_scalars
                .into_iter()
                .fold(Some(expression.clone()), |expression, scalar| 
                    self.scalar(scalar).map(|constant|
                        expression.map(|expr|
                            expr.replace_scalar(scalar, &constant.clone().into())
                                .unwrap())
                    ).unwrap_or(None)
                )?;
        
        eval(&expression).ok()
    }

    // TODO: This is an easy target for optiimization
    pub fn join(self, other: &Constants) -> Constants {
        let mut result = self.clone();
        for (scalar, constant) in other.constants.iter() {
            match self.scalar(scalar) {
                Some(c) => 
                if c != constant {
                    result.set_scalar(scalar.clone(), None);
                }
                else {
                    result.set_scalar(scalar.clone(), None);
                }
                None => result.set_scalar(scalar.clone(), Some(constant.clone()))
            }
        }
        result
    }
}


// We require a struct to implement methods for our analysis over.
struct ConstantsAnalysis {}


impl<'r> fixed_point::FixedPointAnalysis<'r, Constants> for ConstantsAnalysis {
    fn trans(&self, location: il::RefProgramLocation<'r>, state: Option<Constants>)
        -> Result<Constants> {

        let mut state = match state {
            Some(state) => state,
            None => Constants::new()
        };

        let state = match location.instruction() {
            Some(instruction) => match *instruction.operation() {
                il::Operation::Assign { ref dst, ref src } => {
                    let constant = state.eval(src);
                    state.set_scalar(dst.clone(), constant);
                    state
                },
                il::Operation::Load { ref dst, .. } => {
                    state.set_scalar(dst.clone(), None);
                    state
                }
                il::Operation::Store { .. } |
                il::Operation::Branch { .. } |
                il::Operation::Raise { .. } => Constants::new()
            },
            None => state
        };

        Ok(state)
    }


    fn join(&self, state0: Constants, state1: &Constants)
        -> Result<Constants> {
        
        Ok(state0.join(state1))
    }
}
