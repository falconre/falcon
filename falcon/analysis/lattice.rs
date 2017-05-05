//! A lattice for tracking `il::Constant` values.

use executor;
use il;
use il::Expression;
use std::collections::{BTreeMap, BTreeSet};
use std::cmp::{Ord, Ordering, PartialOrd};
use std::fmt;
use std::ops::BitOr;


/// A lattice of `il::Constant` values
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum LatticeValue {
    Join, // Top
    Values(BTreeSet<il::Constant>),
    Meet // Bottom
}

use self::LatticeValue::*;


impl LatticeValue {
    /// Joins the values of the `other` lattice with this lattice by performing
    /// a set union.
    pub fn join(&self, other: &LatticeValue) -> LatticeValue {
        match self {
            &Join => self.clone(),
            &Values(ref lhs_) => {
                match other {
                    &Join => other.clone(),
                    &Values(ref rhs_) => {
                        LatticeValue::Values(lhs_.bitor(rhs_))
                    },
                    &Meet => self.clone()
                }
            },
            &Meet => other.clone()
        }
    }

    /// Takes one `il::Constant` and creates a `LatticeValue::Values` with that
    /// constant as the sole value.
    pub fn value(value: il::Constant) -> LatticeValue {
        let mut set = BTreeSet::new();
        set.insert(value);
        Values(set)
    }
}

impl Ord for LatticeValue {
    fn cmp(&self, other: &Self) -> Ordering {
        match self {
            &Join => {
                match other {
                    &Join => Ordering::Equal,
                    _ => Ordering::Less
                }
            },
            &Values(ref values) => {
                match other {
                    &Join => Ordering::Greater,
                    &Values(ref other_values) => values.cmp(other_values),
                    &Meet => Ordering::Less
                }
            },
            &Meet => {
                match other {
                    &Meet => Ordering::Equal,
                    _ => Ordering::Greater
                }
            }
        }
    }
}

impl PartialOrd for LatticeValue {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl fmt::Display for LatticeValue {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            &Join => write!(f, "Join"),
            &Values(ref values) => {
                write!(f, "({})", values.iter()
                                     .map(|c| format!("{}", c))
                                     .collect::<Vec<String>>()
                                     .join(", "))
            },
            &Meet => write!(f, "Meet")
        }
    }
}



fn lattice_value_binop<F>(lhs: &LatticeValue, rhs: &LatticeValue, op: F) -> LatticeValue
where F: Fn(il::Constant, il::Constant) -> Expression {
    match lhs {
        &Join => LatticeValue::Join,
        &Values(ref lhs_) => {
            match rhs {
                &Join => LatticeValue::Join,
                &Values(ref rhs_) => {
                    let mut sum = BTreeSet::new();
                    for l in lhs_.iter() {
                        for r in rhs_.iter() {
                            let expr = op(l.clone(), r.clone());
                            match executor::constants_expression(&expr) {
                                Ok(c) => { sum.insert(c); },
                                Err(_) => {}
                            }
                        }
                    }
                    LatticeValue::Values(sum)
                },
                &Meet => LatticeValue::Meet
            }
        },
        &Meet => LatticeValue::Meet
    }
}


fn lattice_extend_op<F>(rhs: &LatticeValue, op: F) -> LatticeValue
where F: Fn(il::Constant) -> Expression {
    match rhs {
        &Join => rhs.clone(),
        &Values(ref rhs_) => {
            let mut sum = BTreeSet::new();
            for r in rhs_ {
                let expr = op(r.clone());
                match executor::constants_expression(&expr) {
                    Ok(c) => { sum.insert(c); },
                    Err(_) => {}
                }
            }
            LatticeValue::Values(sum)
        },
        &Meet => rhs.clone()
    }
}


/// A mapping of variables to their lattice values
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct LatticeAssignments {
    /// The value of this lattice
    variables: BTreeMap<il::Variable, LatticeValue>,
    /// The max number of elements for each LatticeValue before converting it
    /// to Join
    max: usize
}


impl LatticeAssignments {
    /// Creates a new LatticeAssignments
    ///
    /// `max` is the maximum number of values a `LatticeValue::Values`s will
    /// hold before being transformed into `LatticeValue::Join`
    pub fn new(max: usize) -> LatticeAssignments {
        LatticeAssignments {
            variables: BTreeMap::new(),
            max: max
        }
    }

    /// Get the `LatticeValue` for a variable
    pub fn value(&self) -> &BTreeMap<il::Variable, LatticeValue> {
        &self.variables
    }

    /// Get max number of values a `LatticeValue` can have before Join
    pub fn max(&self) -> usize {
        self.max
    }

    pub fn join(mut self, other: &LatticeAssignments) -> LatticeAssignments {
        for assignment in &other.variables {
            let variable = assignment.0;
            let mut lattice_value = assignment.1.clone();

            if let Some(lv) = self.variables.get(variable) {
                let lv = lv.join(&lattice_value);
                if let &Values(ref values) = &lv {
                    if values.len() > self.max {
                        lattice_value = LatticeValue::Join
                    }
                    else {
                        lattice_value = lv.clone();
                    }
                }
                else {
                    lattice_value = lv.clone();
                }
            }

            self.variables.insert(variable.clone(), lattice_value);
        }
        self
    }

    /// Set the `LatticeValue` for an `il::Variable`
    pub fn set(&mut self, variable: il::Variable, value: LatticeValue) {
        self.variables.insert(variable, value);
    }

    /// Get the `LatticeValue` for a `Variable`.
    ///
    /// If the variable doesn't exist, set it to `Meet` and return that.
    pub fn get(&self, variable: &il::Variable) -> Option<&LatticeValue> {
        self.variables.get(variable)
    }

    /// Evaluates an `il::Expression`, using the values in this
    /// `LatticeAssignments` for variables.
    pub fn eval(&self, expr: &Expression) -> LatticeValue {
        let lattice_value = self.eval_(expr);
        if let &Values(ref values) = &lattice_value {
            if values.len() > self.max {
                return LatticeValue::Join;
            }
        }
        return lattice_value;
    }

    fn eval_(&self, expr: &Expression) -> LatticeValue {
        match expr {

            &Expression::Variable(ref variable) => {
                match self.variables.get(variable) {
                    Some(lattice_value) => lattice_value.clone(),
                    None => LatticeValue::Meet
                }
            },

            &Expression::Constant(ref constant) =>
                LatticeValue::value(constant.clone()),

            &Expression::Add(ref lhs, ref rhs) => {
                lattice_value_binop(
                    &self.eval_(lhs),
                    &self.eval_(rhs),
                    |lhs: il::Constant, rhs: il::Constant| 
                        Expression::add(lhs.into(), rhs.into()).unwrap()
                )
            },

            &Expression::Sub(ref lhs, ref rhs) => {
                lattice_value_binop(
                    &self.eval_(lhs),
                    &self.eval_(rhs),
                    |lhs: il::Constant, rhs: il::Constant| 
                        Expression::sub(lhs.into(), rhs.into()).unwrap()
                )
            },

            &Expression::Mulu(ref lhs, ref rhs) => {
                lattice_value_binop(
                    &self.eval_(lhs),
                    &self.eval_(rhs),
                    |lhs: il::Constant, rhs: il::Constant| 
                        Expression::mulu(lhs.into(), rhs.into()).unwrap()
                )
            },

            &Expression::Divu(ref lhs, ref rhs) => {
                lattice_value_binop(
                    &self.eval_(lhs),
                    &self.eval_(rhs),
                    |lhs: il::Constant, rhs: il::Constant| 
                        Expression::divu(lhs.into(), rhs.into()).unwrap()
                )
            },

            &Expression::Modu(ref lhs, ref rhs) => {
                lattice_value_binop(
                    &self.eval_(lhs),
                    &self.eval_(rhs),
                    |lhs: il::Constant, rhs: il::Constant| 
                        Expression::modu(lhs.into(), rhs.into()).unwrap()
                )
            },

            &Expression::Muls(ref lhs, ref rhs) => {
                lattice_value_binop(
                    &self.eval_(lhs),
                    &self.eval_(rhs),
                    |lhs: il::Constant, rhs: il::Constant| 
                        Expression::muls(lhs.into(), rhs.into()).unwrap()
                )
            },

            &Expression::Divs(ref lhs, ref rhs) => {
                lattice_value_binop(
                    &self.eval_(lhs),
                    &self.eval_(rhs),
                    |lhs: il::Constant, rhs: il::Constant| 
                        Expression::divs(lhs.into(), rhs.into()).unwrap()
                )
            },

            &Expression::Mods(ref lhs, ref rhs) => {
                lattice_value_binop(
                    &self.eval_(lhs),
                    &self.eval_(rhs),
                    |lhs: il::Constant, rhs: il::Constant| 
                        Expression::mods(lhs.into(), rhs.into()).unwrap()
                )
            },

            &Expression::And(ref lhs, ref rhs) => {
                lattice_value_binop(
                    &self.eval_(lhs),
                    &self.eval_(rhs),
                    |lhs: il::Constant, rhs: il::Constant| 
                        Expression::and(lhs.into(), rhs.into()).unwrap()
                )
            },

            &Expression::Or(ref lhs, ref rhs) => {
                lattice_value_binop(
                    &self.eval_(lhs),
                    &self.eval_(rhs),
                    |lhs: il::Constant, rhs: il::Constant| 
                        Expression::or(lhs.into(), rhs.into()).unwrap()
                )
            },

            &Expression::Xor(ref lhs, ref rhs) => {
                lattice_value_binop(
                    &self.eval_(lhs),
                    &self.eval_(rhs),
                    |lhs: il::Constant, rhs: il::Constant| 
                        Expression::xor(lhs.into(), rhs.into()).unwrap()
                )
            },

            &Expression::Shl(ref lhs, ref rhs) => {
                lattice_value_binop(
                    &self.eval_(lhs),
                    &self.eval_(rhs),
                    |lhs: il::Constant, rhs: il::Constant| 
                        Expression::shl(lhs.into(), rhs.into()).unwrap()
                )
            },

            &Expression::Shr(ref lhs, ref rhs) => {
                lattice_value_binop(
                    &self.eval_(lhs),
                    &self.eval_(rhs),
                    |lhs: il::Constant, rhs: il::Constant| 
                        Expression::shr(lhs.into(), rhs.into()).unwrap()
                )
            },

            &Expression::Cmpeq(ref lhs, ref rhs) => {
                lattice_value_binop(
                    &self.eval_(lhs),
                    &self.eval_(rhs),
                    |lhs: il::Constant, rhs: il::Constant| 
                        Expression::cmpeq(lhs.into(), rhs.into()).unwrap()
                )
            },

            &Expression::Cmpneq(ref lhs, ref rhs) => {
                lattice_value_binop(
                    &self.eval_(lhs),
                    &self.eval_(rhs),
                    |lhs: il::Constant, rhs: il::Constant| 
                        Expression::cmpneq(lhs.into(), rhs.into()).unwrap()
                )
            },

            &Expression::Cmplts(ref lhs, ref rhs) => {
                lattice_value_binop(
                    &self.eval_(lhs),
                    &self.eval_(rhs),
                    |lhs: il::Constant, rhs: il::Constant| 
                        Expression::cmplts(lhs.into(), rhs.into()).unwrap()
                )
            },

            &Expression::Cmpltu(ref lhs, ref rhs) => {
                lattice_value_binop(
                    &self.eval_(lhs),
                    &self.eval_(rhs),
                    |lhs: il::Constant, rhs: il::Constant| 
                        Expression::cmpltu(lhs.into(), rhs.into()).unwrap()
                )
            },

            &Expression::Zext(bits, ref rhs) => {
                lattice_extend_op(
                    &self.eval_(rhs),
                    |rhs: il::Constant| Expression::zext(bits, rhs.into()).unwrap()
                )
            },

            &Expression::Sext(bits, ref rhs) => {
                lattice_extend_op(
                    &self.eval_(rhs),
                    |rhs: il::Constant| Expression::sext(bits, rhs.into()).unwrap()
                )
            },

            &Expression::Trun(bits, ref rhs) => {
                lattice_extend_op(
                    &self.eval_(rhs),
                    |rhs: il::Constant| Expression::trun(bits, rhs.into()).unwrap()
                )
            }
        }
    }
}