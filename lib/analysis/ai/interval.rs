//! An implementation of an interval analysis domain


use analysis::ai;
use analysis::ai::{domain, interpreter};
use analysis::calling_convention::*;
use analysis::fixed_point;
use error::*;
use executor::eval;
use il;
use memory;
use std::cmp::{Ord, Ordering, PartialOrd};
use std::collections::HashMap;
use std::fmt;


/// A `falcon::memory::paged::Memory` set up for interval analysis.
pub type IMemory<'m> = ai::memory::Memory<'m, Interval>;

/// A `falcon::analysis::ai::domain::State` set up for interval analysis.
pub type IState<'m> = domain::State<IMemory<'m>, Interval>;

/// Run ksets analysis on the given function
pub fn interval<'k>(
    function: &'k il::Function,
    calling_convention: CallingConvention,
    initial_memory: IMemory<'k>
) -> Result<HashMap<il::RefProgramLocation<'k>, IState<'k>>> {

    let domain = IntervalDomain { 
        calling_convention: calling_convention,
        memory: initial_memory
    };

    let interpreter = interpreter::Interpreter::new(domain);

    fixed_point::fixed_point_forward_options(interpreter, function, true)
}


/// An interval value, either a constant or infinite
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
pub enum IntervalValue {
    Constant(il::Constant),
    Infinite(usize)
}


/// An interval lattice
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
pub enum Interval {
    Top(usize),
    Interval(IntervalValue, IntervalValue),
    Bottom(usize)
}


impl PartialOrd for Interval {
    fn partial_cmp(&self, other: &Interval) -> Option<Ordering> {
        match *self {
            Interval::Top(_) => match *other {
                Interval::Top(_) => Some(Ordering::Equal),
                Interval::Interval(_, _) |
                Interval::Bottom(_) => Some(Ordering::Greater)
            },
            Interval::Interval(ref llower, ref lupper) => match *other {
                Interval::Top(_) => Some(Ordering::Less),
                Interval::Interval(ref rlower, ref rupper) => {
                    let lower = match *llower {
                        IntervalValue::Infinite(_) => match *rlower {
                            IntervalValue::Infinite(_) => Ordering::Equal,
                            IntervalValue::Constant(_) => Ordering::Less
                        },
                        IntervalValue::Constant(ref lconstant) => match *rlower {
                            IntervalValue::Infinite(_) => Ordering::Greater,
                            IntervalValue::Constant(ref rconstant) => {
                                lconstant.value().cmp(&rconstant.value())
                            }
                        }
                    };
                    let upper = match *lupper {
                        IntervalValue::Infinite(_) => match *rupper {
                            IntervalValue::Infinite(_) => Ordering::Equal,
                            IntervalValue::Constant(_) => Ordering::Greater
                        },
                        IntervalValue::Constant(ref lconstant) => match *rupper {
                            IntervalValue::Infinite(_) => Ordering::Less,
                            IntervalValue::Constant(ref rconstant) => {
                                lconstant.value().cmp(&rconstant.value())
                            }
                        }
                    };
                    match lower {
                        Ordering::Less => match upper {
                            Ordering::Less |
                            Ordering::Equal => Some(Ordering::Less),
                            Ordering::Greater => None
                        },
                        Ordering::Equal => Some(upper),
                        Ordering::Greater => match upper {
                            Ordering::Less => None,
                            Ordering::Equal |
                            Ordering::Greater => Some(Ordering::Greater)
                        }
                    }
                },
                Interval::Bottom(_) => Some(Ordering::Greater)
            },
            Interval::Bottom(_) => match *other {
                Interval::Top(_) |
                Interval::Interval(_, _) => Some(Ordering::Less),
                Interval::Bottom(_) => Some(Ordering::Equal)
            }
        }
    }
}


impl Interval {
    fn binop<F>(lhs: &Interval, rhs: &Interval, op: F) -> Result<Interval>
    where F: Fn(&il::Constant, &il::Constant) -> Result<il::Constant> {
        Ok(match *lhs {
            Interval::Top(bits) => Interval::Top(bits),
            Interval::Interval(ref llower, ref lupper) => {
                match *rhs {
                    Interval::Top(bits) => Interval::Top(bits),
                    Interval::Interval(ref rlower, ref rupper) =>
                        Interval::Interval(match *llower {
                            IntervalValue::Infinite(bits) => IntervalValue::Infinite(bits),
                            IntervalValue::Constant(ref lconstant) => match *rlower {
                                IntervalValue::Infinite(bits) => IntervalValue::Infinite(bits),
                                IntervalValue::Constant(ref rconstant) =>
                                    IntervalValue::Constant(op(lconstant, rconstant)?)
                            }
                        },
                        match *lupper {
                            IntervalValue::Infinite(bits) => IntervalValue::Infinite(bits),
                            IntervalValue::Constant(ref lconstant) => match *rupper {
                                IntervalValue::Infinite(bits) => IntervalValue::Infinite(bits),
                                IntervalValue::Constant(ref rconstant) =>
                                    IntervalValue::Constant(op(lconstant, rconstant)?)
                            }
                        }),
                    Interval::Bottom(bits) => Interval::Bottom(bits),
                }
            },
            Interval::Bottom(bits) => Interval::Bottom(bits)
        })
    }


    fn ext<F>(bits: usize, interval: &Interval, op: F) -> Result<Interval>
    where F: Fn(usize, &il::Constant) -> Result<il::Constant> {
        Ok(match *interval {
            Interval::Top(_) => Interval::Top(bits),
            Interval::Bottom(_) => Interval::Bottom(bits),
            Interval::Interval(ref lower, ref upper) => Interval::Interval(
                match *lower {
                    IntervalValue::Infinite(_) => IntervalValue::Infinite(bits),
                    IntervalValue::Constant(ref c) =>
                        IntervalValue::Constant(op(bits, c)?)
                },
                match *upper {
                    IntervalValue::Infinite(_) => IntervalValue::Infinite(bits),
                    IntervalValue::Constant(ref c) =>
                        IntervalValue::Constant(op(bits, c)?)
                }
            )
        })
    }


    /// Evaluate the given Interval expression, and receive the resulting Interval
    pub fn eval(expr: &domain::Expression<Interval>) -> Result<Interval> {
        match *expr {
            domain::Expression::Value(ref interval) => Ok(interval.clone()),
            domain::Expression::Add(ref lhs, ref rhs) => 
                Interval::binop(&Interval::eval(lhs)?, &Interval::eval(rhs)?, |l, r| {
                    eval(&il::Expression::add(l.clone().into(), r.clone().into())?)
                }),
            domain::Expression::Sub(ref lhs, ref rhs) => 
                Interval::binop(&Interval::eval(lhs)?, &Interval::eval(rhs)?, |l, r| {
                    eval(&il::Expression::sub(l.clone().into(), r.clone().into())?)
                }),
            domain::Expression::Mul(ref lhs, ref rhs) => 
                Interval::binop(&Interval::eval(lhs)?, &Interval::eval(rhs)?, |l, r| {
                    eval(&il::Expression::mul(l.clone().into(), r.clone().into())?)
                }),
            domain::Expression::Divu(ref lhs, ref rhs) => 
                Interval::binop(&Interval::eval(lhs)?, &Interval::eval(rhs)?, |l, r| {
                    eval(&il::Expression::divu(l.clone().into(), r.clone().into())?)
                }),
            domain::Expression::Modu(ref lhs, ref rhs) => 
                Interval::binop(&Interval::eval(lhs)?, &Interval::eval(rhs)?, |l, r| {
                    eval(&il::Expression::modu(l.clone().into(), r.clone().into())?)
                }),
            domain::Expression::Divs(ref lhs, ref rhs) => 
                Interval::binop(&Interval::eval(lhs)?, &Interval::eval(rhs)?, |l, r| {
                    eval(&il::Expression::divs(l.clone().into(), r.clone().into())?)
                }),
            domain::Expression::Mods(ref lhs, ref rhs) => 
                Interval::binop(&Interval::eval(lhs)?, &Interval::eval(rhs)?, |l, r| {
                    eval(&il::Expression::mods(l.clone().into(), r.clone().into())?)
                }),
            domain::Expression::And(ref lhs, ref rhs) => 
                Interval::binop(&Interval::eval(lhs)?, &Interval::eval(rhs)?, |l, r| {
                    eval(&il::Expression::and(l.clone().into(), r.clone().into())?)
                }),
            domain::Expression::Or(ref lhs, ref rhs) => 
                Interval::binop(&Interval::eval(lhs)?, &Interval::eval(rhs)?, |l, r| {
                    eval(&il::Expression::or(l.clone().into(), r.clone().into())?)
                }),
            domain::Expression::Xor(ref lhs, ref rhs) => 
                Interval::binop(&Interval::eval(lhs)?, &Interval::eval(rhs)?, |l, r| {
                    eval(&il::Expression::xor(l.clone().into(), r.clone().into())?)
                }),
            domain::Expression::Shl(ref lhs, ref rhs) => 
                Interval::binop(&Interval::eval(lhs)?, &Interval::eval(rhs)?, |l, r| {
                    eval(&il::Expression::shl(l.clone().into(), r.clone().into())?)
                }),
            domain::Expression::Shr(ref lhs, ref rhs) => 
                Interval::binop(&Interval::eval(lhs)?, &Interval::eval(rhs)?, |l, r| {
                    eval(&il::Expression::shr(l.clone().into(), r.clone().into())?)
                }),
            domain::Expression::Cmpeq(ref lhs, ref rhs) => 
                Interval::binop(&Interval::eval(lhs)?, &Interval::eval(rhs)?, |l, r| {
                    eval(&il::Expression::cmpeq(l.clone().into(), r.clone().into())?)
                }),
            domain::Expression::Cmpneq(ref lhs, ref rhs) => 
                Interval::binop(&Interval::eval(lhs)?, &Interval::eval(rhs)?, |l, r| {
                    eval(&il::Expression::cmpneq(l.clone().into(), r.clone().into())?)
                }),
            domain::Expression::Cmplts(ref lhs, ref rhs) => 
                Interval::binop(&Interval::eval(lhs)?, &Interval::eval(rhs)?, |l, r| {
                    eval(&il::Expression::cmplts(l.clone().into(), r.clone().into())?)
                }),
            domain::Expression::Cmpltu(ref lhs, ref rhs) => 
                Interval::binop(&Interval::eval(lhs)?, &Interval::eval(rhs)?, |l, r| {
                    eval(&il::Expression::cmpltu(l.clone().into(), r.clone().into())?)
                }),
            domain::Expression::Zext(bits, ref v) => 
                Interval::ext(bits, &Interval::eval(v)?, |bits, v| {
                    eval(&il::Expression::zext(bits, v.clone().into())?)
                }),
            domain::Expression::Sext(bits, ref v) => 
                Interval::ext(bits, &Interval::eval(v)?, |bits, v| {
                    eval(&il::Expression::sext(bits, v.clone().into())?)
                }),
            domain::Expression::Trun(bits, ref v) => 
                Interval::ext(bits, &Interval::eval(v)?, |bits, v| {
                    eval(&il::Expression::trun(bits, v.clone().into())?)
                })
        }
    }

    /// Retrieve the size of this `Interval` in bits
    pub fn bits(&self) -> usize {
        match *self {
            Interval::Top(bits) => bits,
            Interval::Bottom(bits) => bits,
            Interval::Interval(ref lower, _) => match *lower {
                IntervalValue::Constant(ref c) => c.bits(),
                IntervalValue::Infinite(bits) => bits
            }
        }
    }

    /// Create an `Interval` from an `il::Constant`
    pub fn constant(constant: il::Constant) -> Interval {
        Interval::Interval(IntervalValue::Constant(constant.clone()),
                           IntervalValue::Constant(constant))
    }

    /// Apply the widening operator between this interval and the given interval
    pub fn widen(&self, other: &Interval) -> Result<Interval> {
        fn widen_value(this: &IntervalValue, other: &IntervalValue) -> IntervalValue {
            match *this {
                IntervalValue::Infinite(bits) => IntervalValue::Infinite(bits),
                IntervalValue::Constant(ref lconstant) => match *other {
                    IntervalValue::Infinite(bits) => IntervalValue::Infinite(bits),
                    IntervalValue::Constant(ref rconstant) => {
                        if lconstant.value() != rconstant.value() {
                            IntervalValue::Infinite(lconstant.bits())
                        }
                        else {
                            this.clone()
                        }
                    }
                }
            }
        }

        Ok(match *self {
            Interval::Top(bits) => Interval::Top(bits),
            Interval::Interval(ref llower, ref lupper) => match *other {
                Interval::Top(bits) => Interval::Top(bits),
                Interval::Interval(ref rlower, ref rupper) =>
                    Interval::Interval(widen_value(llower, rlower),
                                       widen_value(lupper, rupper)),
                Interval::Bottom(_) => self.clone()
            },
            Interval::Bottom(_) => other.clone()
        })
    }

    /// Join two `Interval` together.
    pub fn join(&self, rhs: &Interval) -> Result<Interval> {
        Ok(match *self {
            Interval::Top(bits) => Interval::Top(bits),
            Interval::Interval(ref llower, ref lupper) => match *rhs {
                Interval::Top(bits) => Interval::Top(bits),
                Interval::Interval(ref rlower, ref rupper) =>
                    Interval::Interval(match *llower {
                        IntervalValue::Infinite(bits) => IntervalValue::Infinite(bits),
                        IntervalValue::Constant(ref lconstant) => match *rlower {
                            IntervalValue::Infinite(bits) => IntervalValue::Infinite(bits),
                            IntervalValue::Constant(ref rconstant) => {
                                if lconstant.value() < rconstant.value() {
                                    IntervalValue::Constant(lconstant.clone())
                                }
                                else {
                                    IntervalValue::Constant(rconstant.clone())
                                }
                            }
                        }
                    },
                    match *lupper {
                        IntervalValue::Infinite(bits) => IntervalValue::Infinite(bits),
                        IntervalValue::Constant(ref lconstant) => match *rupper {
                            IntervalValue::Infinite(bits) => IntervalValue::Infinite(bits),
                            IntervalValue::Constant(ref rconstant) => {
                                if lconstant.value() < rconstant.value() {
                                    IntervalValue::Constant(lconstant.clone())
                                }
                                else {
                                    IntervalValue::Constant(rconstant.clone())
                                }
                            }
                        }
                    }),
                Interval::Bottom(_) => self.clone()
            },
            Interval::Bottom(_) => rhs.clone()
        })
    }

    /// Create a `KSet` representing an empty value.
    pub fn empty(bits: usize) -> Interval {
        Interval::Bottom(bits)
    }
}


impl Into<domain::Expression<Interval>> for Interval {
    fn into(self) -> domain::Expression<Interval> {
        domain::Expression::Value(self)
    }
}


impl memory::value::Value for Interval {
    fn constant(constant: il::Constant) -> Interval {
        Interval::constant(constant)
    }

    fn bits(&self) -> usize {
        self.bits()
    }

    fn shl(&self, bits: usize) -> Result<Interval> {
        Interval::eval(&domain::Expression::shl(
            self.clone().into(),
            Interval::constant(il::const_(bits as u64, self.bits())).into()
        ))
    }

    fn shr(&self, bits: usize) -> Result<Interval> {
        Interval::eval(&domain::Expression::shr(
            self.clone().into(),
            Interval::constant(il::const_(bits as u64, self.bits())).into()
        ))
    }

    fn trun(&self, bits: usize) -> Result<Interval> {
        Interval::eval(&domain::Expression::trun(bits, self.clone().into()))
    }

    fn zext(&self, bits: usize) -> Result<Interval> {
        Interval::eval(&domain::Expression::zext(bits, self.clone().into()))
    }

    fn or(&self, other: &Interval) -> Result<Interval> {
        Interval::eval(&domain::Expression::or(
            self.clone().into(),
            other.clone().into()
        ))
    }
}


impl domain::Value for Interval {
    fn join(&self, other: &Interval) -> Result<Interval> {
        self.join(other)
    }

    fn bottom(bits: usize) -> Interval {
        Interval::Bottom(bits)
    }

    fn top(bits: usize) -> Interval {
        Interval::Top(bits)
    }

    fn constant(constant: il::Constant) -> Interval {
        Interval::constant(constant)
    }
}


struct IntervalDomain<'m> {
    calling_convention: CallingConvention,
    memory: IMemory<'m>
}


impl<'m> domain::Domain<IMemory<'m>, Interval> for IntervalDomain<'m> {
    fn eval(&self, expr: &domain::Expression<Interval>) -> Result<Interval> {
        Interval::eval(expr)
    }

    fn store(&self, memory: &mut IMemory, index: &Interval, value: Interval)
        -> Result<()> {

        match *index {
            Interval::Interval(ref lower, ref upper) => {
                match *lower {
                    IntervalValue::Infinite(_) => {},
                    IntervalValue::Constant(ref lconstant) => match *upper {
                        IntervalValue::Infinite(_) => {},
                        IntervalValue::Constant(ref rconstant) => {
                            for i in lconstant.value()..(rconstant.value() + 1) {
                                memory.store_weak(i, &value)?;
                            }
                        }
                    }
                }
            },
            _ => {}
        }
        Ok(())
    }

    fn load(&self, memory: &IMemory, index: &Interval, bits: usize)
        -> Result<Interval> {

        match *index {
            Interval::Interval(ref lower, ref upper) =>
                Ok(match *lower {
                    IntervalValue::Infinite(_) => Interval::Top(bits),
                    IntervalValue::Constant(ref lconstant) => match *upper {
                        IntervalValue::Infinite(_) => Interval::Top(bits),
                        IntervalValue::Constant(ref rconstant) => {
                            let mut i = Interval::empty(bits);
                            for address in lconstant.value()..(rconstant.value() + 1) {
                                i = i.join(&memory.load(address, bits)?)?;
                            }
                            i
                        }
                    }
                }),
            Interval::Top(bits) |
            Interval::Bottom(bits) => Ok(Interval::Top(bits))
        }
    }

    fn brc(&self, _: &Interval, mut state: IState<'m>) -> Result<IState<'m>> {
        for trashed_register in self.calling_convention.trashed_registers() {
            state.remove_variable(trashed_register);
        }
        Ok(state)
    }

    fn raise(&self, _: &Interval, state: IState<'m>) -> Result<IState<'m>> {
        Ok(state)
    }

    fn new_state(&self) -> IState<'m> {
        IState::new(self.memory.clone())
    }
}


impl fmt::Display for IntervalValue {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            IntervalValue::Infinite(bits) => write!(f, "∞:{}", bits),
            IntervalValue::Constant(ref c) => c.fmt(f)
        }
    }
}


impl fmt::Display for Interval {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Interval::Top(bits) => write!(f, "⊤:{}", bits),
            Interval::Bottom(bits) => write!(f, "⊥:{}", bits),
            Interval::Interval(ref lower, ref upper) => 
                write!(f, "<{},{}>", lower, upper)
        }
    }
}


impl fmt::Debug for Interval {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self)
    }
}