//! An implementation of the KSet analysis domain
//!
//! ```
//! # use falcon::error::*;
//! use falcon::analysis::ai::kset;
//! use falcon::loader::Elf;
//! use falcon::loader::Loader;
//! use std::path::Path;
//!
//! # fn example () -> Result<()> {
//! // Load an elf for analysis
//! let elf = Elf::from_file(Path::new("test_binaries/simple-0/simple-0"))?;
//! // Get the endianness of the architecture for this elf
//! let endian = elf.architecture()?.endian();
//! // Get the underlying memory of this Elf as a memory backing
//! let backing = elf.memory()?;
//! // Lift one function from the Elf at address 0x804849b
//! let function = elf.function(0x804849b)?;
//! // Set up a memory model for this analysis
//! let memory: kset::KMemory =
//!     kset::KMemory::new_with_backing(endian.clone(), &backing);
//! // Run the ksets analysis
//! let ksets = kset::kset(&function, endian, memory)?;
//! # Ok(())
//! # }
//! ```


use analysis::ai;
use analysis::ai::{domain, interpreter};
use analysis::fixed_point;
use error::*;
use executor::eval;
use il;
use memory;
use std::collections::{HashMap, HashSet};
use std::fmt;
use types::Endian;


/// The cardinality for this analysis.
pub const MAX_CARDINALITY: usize = 4;


/// A `falcon::memory::paged::Memory` set up for ksets analysis.
pub type KMemory<'m> = ai::memory::Memory<'m, KSet>;

/// A `falcon::analysis::ai::domain::State` set up for ksets analysis.
pub type KState<'m> = domain::State<KMemory<'m>, KSet>;

/// Run ksets analysis on the given function
pub fn kset<'k>(function: &'k il::Function, endian: Endian, initial_memory: KMemory<'k>)
    -> Result<HashMap<il::RefProgramLocation<'k>, KState<'k>>> {

    let domain = KSetDomain { endian: endian, memory: initial_memory };
    let interpreter = interpreter::Interpreter {
        m: ::std::marker::PhantomData,
        v: ::std::marker::PhantomData,
        domain: domain
    };
    fixed_point::fixed_point_forward(interpreter, function)
}


/// A KSet
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum KSet {
    Top(usize),
    Value(HashSet<il::Constant>),
    Bottom(usize)
}



impl KSet {
    fn binop<F>(lhs: &KSet, rhs: &KSet, op: F) -> Result<KSet>
    where F: Fn(&il::Constant, &il::Constant) -> Result<il::Constant> {
        Ok(match *lhs {
            KSet::Top(bits) => KSet::Top(bits),
            KSet::Bottom(bits) => KSet::Bottom(bits),
            KSet::Value(ref lhs_value) => {
                match *rhs {
                    KSet::Top(bits) => KSet::Top(bits),
                    KSet::Bottom(bits) => KSet::Bottom(bits),
                    KSet::Value(ref rhs_value) => {
                        let mut b: HashSet<il::Constant> = HashSet::new();
                        for l in lhs_value {
                            for r in rhs_value {
                                b.insert(op(l, r)?);
                            }
                            if b.len() > MAX_CARDINALITY {
                                return Ok(KSet::Top(b.iter().next().unwrap().bits()));
                            }
                        }
                        if b.len() > MAX_CARDINALITY {
                            KSet::Top(b.iter().next().unwrap().bits())
                        }
                        else {
                            KSet::Value(b)
                        }
                    }
                }
            }
        })
    }


    fn ext<F>(bits: usize, k: &KSet, op: F) -> Result<KSet>
    where F: Fn(usize, &il::Constant) -> Result<il::Constant> {
        Ok(match *k {
            KSet::Top(_) => KSet::Top(bits),
            KSet::Bottom(_) => KSet::Bottom(bits),
            KSet::Value(ref value) => {
                let mut b: HashSet<il::Constant> = HashSet::new();
                for v in value {
                    b.insert(op(bits, v)?);
                }
                KSet::Value(b)
            }
        })
    }


    /// Evaluate the given KSet expression, and receive the resulting KSet
    pub fn eval(expr: &domain::Expression<KSet>) -> Result<KSet> {
        match *expr {
            domain::Expression::Value(ref kset) => Ok(kset.clone()),
            domain::Expression::Add(ref lhs, ref rhs) => 
                KSet::binop(&KSet::eval(lhs)?, &KSet::eval(rhs)?, |l, r| {
                    eval(&il::Expression::add(l.clone().into(), r.clone().into())?)
                }),
            domain::Expression::Sub(ref lhs, ref rhs) => 
                KSet::binop(&KSet::eval(lhs)?, &KSet::eval(rhs)?, |l, r| {
                    eval(&il::Expression::sub(l.clone().into(), r.clone().into())?)
                }),
            domain::Expression::Mul(ref lhs, ref rhs) => 
                KSet::binop(&KSet::eval(lhs)?, &KSet::eval(rhs)?, |l, r| {
                    eval(&il::Expression::mul(l.clone().into(), r.clone().into())?)
                }),
            domain::Expression::Divu(ref lhs, ref rhs) => 
                KSet::binop(&KSet::eval(lhs)?, &KSet::eval(rhs)?, |l, r| {
                    eval(&il::Expression::divu(l.clone().into(), r.clone().into())?)
                }),
            domain::Expression::Modu(ref lhs, ref rhs) => 
                KSet::binop(&KSet::eval(lhs)?, &KSet::eval(rhs)?, |l, r| {
                    eval(&il::Expression::modu(l.clone().into(), r.clone().into())?)
                }),
            domain::Expression::Divs(ref lhs, ref rhs) => 
                KSet::binop(&KSet::eval(lhs)?, &KSet::eval(rhs)?, |l, r| {
                    eval(&il::Expression::divs(l.clone().into(), r.clone().into())?)
                }),
            domain::Expression::Mods(ref lhs, ref rhs) => 
                KSet::binop(&KSet::eval(lhs)?, &KSet::eval(rhs)?, |l, r| {
                    eval(&il::Expression::mods(l.clone().into(), r.clone().into())?)
                }),
            domain::Expression::And(ref lhs, ref rhs) => 
                KSet::binop(&KSet::eval(lhs)?, &KSet::eval(rhs)?, |l, r| {
                    eval(&il::Expression::and(l.clone().into(), r.clone().into())?)
                }),
            domain::Expression::Or(ref lhs, ref rhs) => 
                KSet::binop(&KSet::eval(lhs)?, &KSet::eval(rhs)?, |l, r| {
                    eval(&il::Expression::or(l.clone().into(), r.clone().into())?)
                }),
            domain::Expression::Xor(ref lhs, ref rhs) => 
                KSet::binop(&KSet::eval(lhs)?, &KSet::eval(rhs)?, |l, r| {
                    eval(&il::Expression::xor(l.clone().into(), r.clone().into())?)
                }),
            domain::Expression::Shl(ref lhs, ref rhs) => 
                KSet::binop(&KSet::eval(lhs)?, &KSet::eval(rhs)?, |l, r| {
                    eval(&il::Expression::shl(l.clone().into(), r.clone().into())?)
                }),
            domain::Expression::Shr(ref lhs, ref rhs) => 
                KSet::binop(&KSet::eval(lhs)?, &KSet::eval(rhs)?, |l, r| {
                    eval(&il::Expression::shr(l.clone().into(), r.clone().into())?)
                }),
            domain::Expression::Cmpeq(ref lhs, ref rhs) => 
                KSet::binop(&KSet::eval(lhs)?, &KSet::eval(rhs)?, |l, r| {
                    eval(&il::Expression::cmpeq(l.clone().into(), r.clone().into())?)
                }),
            domain::Expression::Cmpneq(ref lhs, ref rhs) => 
                KSet::binop(&KSet::eval(lhs)?, &KSet::eval(rhs)?, |l, r| {
                    eval(&il::Expression::cmpneq(l.clone().into(), r.clone().into())?)
                }),
            domain::Expression::Cmplts(ref lhs, ref rhs) => 
                KSet::binop(&KSet::eval(lhs)?, &KSet::eval(rhs)?, |l, r| {
                    eval(&il::Expression::cmplts(l.clone().into(), r.clone().into())?)
                }),
            domain::Expression::Cmpltu(ref lhs, ref rhs) => 
                KSet::binop(&KSet::eval(lhs)?, &KSet::eval(rhs)?, |l, r| {
                    eval(&il::Expression::cmpltu(l.clone().into(), r.clone().into())?)
                }),
            domain::Expression::Zext(bits, ref v) => 
                KSet::ext(bits, &KSet::eval(v)?, |bits, v| {
                    eval(&il::Expression::zext(bits, v.clone().into())?)
                }),
            domain::Expression::Sext(bits, ref v) => 
                KSet::ext(bits, &KSet::eval(v)?, |bits, v| {
                    eval(&il::Expression::sext(bits, v.clone().into())?)
                }),
            domain::Expression::Trun(bits, ref v) => 
                KSet::ext(bits, &KSet::eval(v)?, |bits, v| {
                    eval(&il::Expression::trun(bits, v.clone().into())?)
                })
        }
    }

    /// Retrieve the size of this `KSet` in bits
    pub fn bits(&self) -> usize {
        match *self {
            KSet::Top(bits) => bits,
            KSet::Bottom(bits) => bits,
            KSet::Value(ref v) => v.iter().next().unwrap().bits()
        }
    }

    /// Create a `KSet` from an `il::Constant`
    pub fn constant(constant: il::Constant) -> KSet {
        let mut b = HashSet::new();
        b.insert(constant);
        KSet::Value(b)
    }

    /// Join two `KSet` together.
    pub fn join(&self, rhs: &KSet) -> Result<KSet> {
        Ok(match *self {
            KSet::Top(bits) => KSet::Top(bits),
            KSet::Bottom(_) => rhs.clone(),
            KSet::Value(ref lhs_value) => {
                match *rhs {
                    KSet::Top(bits) => KSet::Top(bits),
                    KSet::Bottom(_) => self.clone(),
                    KSet::Value(ref rhs_value) => {
                        let mut lhs_value = lhs_value.clone();
                        for r in rhs_value {
                            lhs_value.insert(r.clone());
                        }
                        if lhs_value.len() > MAX_CARDINALITY {
                            KSet::Top(lhs_value.iter().next().unwrap().bits())
                        }
                        else {
                            KSet::Value(lhs_value)
                        }
                    }
                }
            }
        })
    }

    /// Create a `KSet` representing an empty value.
    pub fn empty(bits: usize) -> KSet {
        KSet::Bottom(bits)
    }
}


impl Into<domain::Expression<KSet>> for KSet {
    fn into(self) -> domain::Expression<KSet> {
        domain::Expression::Value(self)
    }
}


impl memory::value::Value for KSet {
    fn constant(constant: il::Constant) -> KSet {
        KSet::constant(constant)
    }

    fn bits(&self) -> usize {
        self.bits()
    }

    fn shl(&self, bits: usize) -> Result<KSet> {
        KSet::eval(&domain::Expression::shl(
            self.clone().into(),
            KSet::constant(il::const_(bits as u64, self.bits())).into()
        ))
    }

    fn shr(&self, bits: usize) -> Result<KSet> {
        KSet::eval(&domain::Expression::shr(
            self.clone().into(),
            KSet::constant(il::const_(bits as u64, self.bits())).into()
        ))
    }

    fn trun(&self, bits: usize) -> Result<KSet> {
        KSet::eval(&domain::Expression::trun(bits, self.clone().into()))
    }

    fn zext(&self, bits: usize) -> Result<KSet> {
        KSet::eval(&domain::Expression::zext(bits, self.clone().into()))
    }

    fn or(&self, other: &KSet) -> Result<KSet> {
        KSet::eval(&domain::Expression::or(
            self.clone().into(),
            other.clone().into()
        ))
    }
}


impl ai::memory::Value for KSet {
    fn join(&self, other: &KSet) -> Result<KSet> {
        KSet::join(self, other)
    }

    fn empty(bits: usize) -> KSet {
        KSet::empty(bits)
    }
}


impl domain::Value for KSet {
    fn join(&self, other: &KSet) -> Result<KSet> {
        self.join(other)
    }

    fn empty(bits: usize) -> KSet {
        KSet::empty(bits)
    }

    fn constant(constant: il::Constant) -> KSet {
        KSet::constant(constant)
    }
}


impl<'m> domain::Memory<KSet> for KMemory<'m> {
    fn store(&mut self, index: &KSet, value: KSet) -> Result<()> {
        if let KSet::Value(ref kindex) = *index {
            for i in kindex {
                self.store(i.value(), value.clone())?
            }
        }
        Ok(())
    }

    fn load(&self, index: &KSet, bits: usize) -> Result<KSet> {
        if let KSet::Value(ref kindex) = *index {
            let mut b = KSet::empty(index.bits());
            for i in kindex {
                b = b.join(&self.load(i.value(), bits)?)?;
            }
            Ok(b)
        }
        else {
            Ok(KSet::empty(index.bits()))
        }
    }

    fn new(endian: Endian) -> KMemory<'m> {
        ai::memory::Memory::<KSet>::new(endian)
    }

    fn join(self, other: &KMemory) -> Result<KMemory<'m>> {
        ai::memory::Memory::<KSet>::join(self, other)
    }
}


struct KSetDomain<'m> {
    endian: Endian,
    memory: KMemory<'m>
}


impl<'m> domain::Domain<KMemory<'m>, KSet> for KSetDomain<'m> {
    fn eval(&self, expr: &domain::Expression<KSet>) -> Result<KSet> {
        KSet::eval(expr)
    } 

    fn brc(&self, _: &KSet, _: &KSet, state: KState<'m>) -> Result<KState<'m>> {
        Ok(state)
    }

    fn raise(&self, _: &KSet, state: KState<'m>) -> Result<KState<'m>> {
        Ok(state)
    }

    fn endian(&self) -> Endian {
        self.endian.clone()
    }

    fn new_state(&self) -> KState<'m> {
        KState {
            variables: HashMap::new(),
            memory: self.memory.clone()
        }
    }
}


impl fmt::Display for KSet {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            KSet::Top(bits) => write!(f, "⊤:{}", bits),
            KSet::Bottom(bits) => write!(f, "⊥:{}", bits),
            KSet::Value(ref values) => write!(f, "{{{}}}", values
                .iter()
                .map(|v| format!("{}", v))
                .collect::<Vec<String>>()
                .join(","))
        }
    }
}


impl<'m> Into<HashMap<il::Scalar, KSet>> for KState<'m> {
    fn into(self) -> HashMap<il::Scalar, KSet> {
        self.variables
    }
}