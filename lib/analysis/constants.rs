//! A very simple, and fast, constant propagation
//!
//! Each location has the known constant values for all variables before
//! execution of that location.
//!
//! Calling Constants::eval() uses the known constant values to replace scalars,
//! and then attempts to evaluate the expression to an `il::Constant`.

use crate::analysis::fixed_point;
use crate::executor::eval;
use crate::il;
use crate::Error;
use serde::{Deserialize, Serialize};
use std::cmp::{Ordering, PartialOrd};
use std::collections::HashMap;

/// Compute constants for the given function
pub fn constants(
    function: &il::Function,
) -> Result<HashMap<il::ProgramLocation, Constants>, Error> {
    let constants = fixed_point::fixed_point_forward(ConstantsAnalysis {}, function)?;

    // we're now going to remap constants, so each position holds the values of
    // constants immediately preceeding its execution.

    let mut result = HashMap::new();

    for location in constants.keys() {
        let rfl = location.function_location().apply(function).unwrap();
        let rpl = il::RefProgramLocation::new(function, rfl);
        result.insert(
            location.clone(),
            rpl.backward()?
                .into_iter()
                .fold(Constants::new(), |c, location| {
                    c.join(&constants[&location.into()])
                }),
        );
    }

    Ok(result)
}

#[allow(dead_code)] // Bottom is never used
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
enum Constant {
    Top,
    Constant(il::Constant),
    Bottom,
}

impl Constant {
    fn get(&self) -> Option<&il::Constant> {
        match *self {
            Constant::Constant(ref constant) => Some(constant),
            Constant::Top | Constant::Bottom => None,
        }
    }
}

impl PartialOrd for Constant {
    fn partial_cmp(&self, other: &Constant) -> Option<Ordering> {
        match *self {
            Constant::Top => match *other {
                Constant::Top => Some(Ordering::Equal),
                Constant::Constant(_) | Constant::Bottom => Some(Ordering::Greater),
            },
            Constant::Constant(ref lc) => match *other {
                Constant::Top => Some(Ordering::Less),
                Constant::Constant(ref rc) => {
                    if lc == rc {
                        Some(Ordering::Equal)
                    } else {
                        None
                    }
                }
                Constant::Bottom => Some(Ordering::Greater),
            },
            Constant::Bottom => match *other {
                Constant::Top | Constant::Constant(_) => Some(Ordering::Less),
                Constant::Bottom => Some(Ordering::Equal),
            },
        }
    }
}

/// The value of all constants before the `RefProgramLocation` is evaluated.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct Constants {
    constants: HashMap<il::Scalar, Constant>,
}

impl PartialOrd for Constants {
    fn partial_cmp(&self, other: &Constants) -> Option<Ordering> {
        match self.constants.len().cmp(&other.constants.len()) {
            Ordering::Less => {
                for (ls, lc) in self.constants.iter() {
                    if !other.constants.get(ls).map(|rc| lc <= rc).unwrap_or(false) {
                        return None;
                    }
                }
                Some(Ordering::Less)
            }
            Ordering::Greater => {
                for (ls, lc) in other.constants.iter() {
                    if !self.constants.get(ls).map(|rc| lc <= rc).unwrap_or(false) {
                        return None;
                    }
                }
                Some(Ordering::Greater)
            }
            Ordering::Equal => {
                let mut order = Ordering::Equal;
                for (ls, lc) in &self.constants {
                    match other.constants.get(ls) {
                        Some(rc) => {
                            if lc < rc {
                                if order <= Ordering::Equal {
                                    order = Ordering::Less;
                                } else {
                                    return None;
                                }
                            } else if lc > rc {
                                if order >= Ordering::Equal {
                                    order = Ordering::Greater;
                                } else {
                                    return None;
                                }
                            }
                        }
                        None => {
                            return None;
                        }
                    }
                }
                Some(order)
            }
        }
    }
}

impl Constants {
    fn new() -> Constants {
        Constants {
            constants: HashMap::new(),
        }
    }

    /// Get the constant value for a scalar, if it exists.
    pub fn scalar(&self, scalar: &il::Scalar) -> Option<&il::Constant> {
        self.constants
            .get(scalar)
            .and_then(|constant| constant.get())
    }

    fn set_scalar(&mut self, scalar: il::Scalar, constant: Constant) {
        self.constants.insert(scalar, constant);
    }

    fn top(&mut self) {
        self.constants
            .iter_mut()
            .for_each(|(_, constant)| *constant = Constant::Top);
    }

    /// Attempt to reduce an expression down to a constant, using the constants
    /// found by this analysis.
    pub fn eval(&self, expression: &il::Expression) -> Option<il::Constant> {
        let expression_scalars = expression.scalars();

        let expression = expression_scalars.into_iter().fold(
            Some(expression.clone()),
            |expression, scalar| {
                self.scalar(scalar).and_then(|constant| {
                    expression.map(|expr| {
                        expr.replace_scalar(scalar, &constant.clone().into())
                            .unwrap()
                    })
                })
            },
        )?;

        eval(&expression).ok()
    }

    fn join(self, other: &Constants) -> Constants {
        let mut result = self.clone();
        for (scalar, constant) in other.constants.iter() {
            match self.constants.get(scalar) {
                Some(c) => {
                    if c != constant {
                        result.set_scalar(scalar.clone(), Constant::Top);
                    }
                }
                None => result.set_scalar(scalar.clone(), constant.clone()),
            }
        }
        result
    }
}

// We require a struct to implement methods for our analysis over.
struct ConstantsAnalysis {}

impl<'r> fixed_point::FixedPointAnalysis<'r, Constants> for ConstantsAnalysis {
    fn trans(
        &self,
        location: il::RefProgramLocation<'r>,
        state: Option<Constants>,
    ) -> Result<Constants, Error> {
        let mut state = match state {
            Some(state) => state,
            None => Constants::new(),
        };

        let state = match location.instruction() {
            Some(instruction) => match *instruction.operation() {
                il::Operation::Assign { ref dst, ref src } => {
                    let constant = state
                        .eval(src)
                        .map(Constant::Constant)
                        .unwrap_or(Constant::Top);
                    state.set_scalar(dst.clone(), constant);
                    state
                }
                il::Operation::Load { ref dst, .. } => {
                    state.set_scalar(dst.clone(), Constant::Top);
                    state
                }
                il::Operation::Store { .. } => state,
                il::Operation::Branch { .. } => {
                    state.top();
                    state
                }
                il::Operation::Intrinsic { ref intrinsic } => {
                    if let Some(scalars_written) = intrinsic.scalars_written() {
                        scalars_written
                            .into_iter()
                            .for_each(|scalar| state.set_scalar(scalar.clone(), Constant::Top));
                    } else {
                        state.top();
                    }
                    state
                }
                il::Operation::Nop { .. } => state,
            },
            None => state,
        };

        Ok(state)
    }

    fn join(&self, state0: Constants, state1: &Constants) -> Result<Constants, Error> {
        Ok(state0.join(state1))
    }
}
