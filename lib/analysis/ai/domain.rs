//! Abstractions/traits for an Abstract Domain

use error::*;
use il;
use serde::Serialize;
use std::collections::{HashMap};
use std::cmp::{Ordering, PartialEq, PartialOrd};
use std::fmt::Debug;


/// An abstract value
pub trait Value: Clone + Debug + PartialEq + PartialOrd {
    /// Join this abstract value with another
    fn join(&self, other: &Self) -> Result<Self>;

    /// Return an top abstract value
    fn top(bits: usize) -> Self;

    /// Return an bottom abstract value
    fn bottom(bits: usize) -> Self;

    /// Take an il::Constant, and turn it into an abstract value
    fn constant(constant: il::Constant) -> Self; 
}


/// A memory model which operates over abstract values
pub trait Memory<V: Value>: Clone + Debug + PartialEq + PartialOrd + Serialize {
    /// Join this memory with another memory
    fn join(self, other: &Self) -> Result<Self>;

    /// Return this memory with all values set to top.
    fn top(&mut self) -> Result<()>;
}


/// An abstract domain which handles all operations required for the abstract
/// interpreter.
pub trait Domain<M: Memory<V>, V: Value> {
    /// Evaluate an expression of abstract values
    fn eval(&self, expr: &Expression<V>) -> Result<V>;

    /// Handle a store operation
    fn store(&self, memory: &mut M, index: &V, value: V) -> Result<()>;

    /// Handle a load operation
    fn load(&self, memory: &M, index: &V, bits: usize) -> Result<V>;

    /// Handle a brc operation
    fn brc(&self, target: &V, condition: &V, state: State<M, V>) -> Result<State<M, V>>;

    /// Handle a raise operation
    fn raise(&self, expr: &V, state: State<M, V>) -> Result<State<M, V>>;

    /// Return an empty state
    fn new_state(&self) -> State<M, V>;
}


/// An abstract expression
///
/// This is a slightly modified version of a regular Falcon IL expression, where
/// Scalar and Constant are replaced with Value
#[derive(Clone, Debug)]
pub enum Expression<V: Clone> {
    Value(V),
    Add(Box<Expression<V>>, Box<Expression<V>>),
    Sub(Box<Expression<V>>, Box<Expression<V>>),
    Mul(Box<Expression<V>>, Box<Expression<V>>),
    Divu(Box<Expression<V>>, Box<Expression<V>>),
    Modu(Box<Expression<V>>, Box<Expression<V>>),
    Divs(Box<Expression<V>>, Box<Expression<V>>),
    Mods(Box<Expression<V>>, Box<Expression<V>>),
    And(Box<Expression<V>>, Box<Expression<V>>),
    Or(Box<Expression<V>>, Box<Expression<V>>),
    Xor(Box<Expression<V>>, Box<Expression<V>>),
    Shl(Box<Expression<V>>, Box<Expression<V>>),
    Shr(Box<Expression<V>>, Box<Expression<V>>),
    Cmpeq(Box<Expression<V>>, Box<Expression<V>>),
    Cmpneq(Box<Expression<V>>, Box<Expression<V>>),
    Cmpltu(Box<Expression<V>>, Box<Expression<V>>),
    Cmplts(Box<Expression<V>>, Box<Expression<V>>),
    Zext(usize, Box<Expression<V>>),
    Sext(usize, Box<Expression<V>>),
    Trun(usize, Box<Expression<V>>),
}


#[macro_use]
macro_rules! expression_binop {
    ($p: path, $n: ident) => {
        pub fn $n(lhs: Expression<V>, rhs: Expression<V>) -> Expression<V> {
            $p(Box::new(lhs), Box::new(rhs))
        }
    }
}


#[macro_use]
macro_rules! expression_extop {
    ($p: path, $n: ident) => {
        pub fn $n(bits: usize, rhs: Expression<V>) -> Expression<V> {
            $p(bits, Box::new(rhs))
        }
    }
}


impl<V> Expression<V> where V: Clone {
    pub fn value(value: V) -> Expression<V> {
        Expression::Value(value)
    }
    expression_binop!(Expression::Add, add);
    expression_binop!(Expression::Sub, sub);
    expression_binop!(Expression::Mul, mul);
    expression_binop!(Expression::Divu, divu);
    expression_binop!(Expression::Modu, modu);
    expression_binop!(Expression::Divs, divs);
    expression_binop!(Expression::Mods, mods);
    expression_binop!(Expression::And, and);
    expression_binop!(Expression::Or, or);
    expression_binop!(Expression::Xor, xor);
    expression_binop!(Expression::Shl, shl);
    expression_binop!(Expression::Shr, shr);
    expression_binop!(Expression::Cmpeq, cmpeq);
    expression_binop!(Expression::Cmpneq, cmpneq);
    expression_binop!(Expression::Cmpltu, cmpltu);
    expression_binop!(Expression::Cmplts, cmplts);
    expression_extop!(Expression::Zext, zext);
    expression_extop!(Expression::Sext, sext);
    expression_extop!(Expression::Trun, trun);
    pub fn into_<W>(self) -> Expression<W> where V: Into<W>, W: Clone {
        match self {
            Expression::Value(v) => Expression::Value(v.into()),
            Expression::Add(lhs, rhs) => Expression::add(lhs.into_(), rhs.into_()),
            Expression::Sub(lhs, rhs) => Expression::sub(lhs.into_(), rhs.into_()),
            Expression::Mul(lhs, rhs) => Expression::mul(lhs.into_(), rhs.into_()),
            Expression::Divu(lhs, rhs) => Expression::divu(lhs.into_(), rhs.into_()),
            Expression::Modu(lhs, rhs) => Expression::modu(lhs.into_(), rhs.into_()),
            Expression::Divs(lhs, rhs) => Expression::divs(lhs.into_(), rhs.into_()),
            Expression::Mods(lhs, rhs) => Expression::mods(lhs.into_(), rhs.into_()),
            Expression::And(lhs, rhs) => Expression::and(lhs.into_(), rhs.into_()),
            Expression::Or(lhs, rhs) => Expression::or(lhs.into_(), rhs.into_()),
            Expression::Xor(lhs, rhs) => Expression::xor(lhs.into_(), rhs.into_()),
            Expression::Shl(lhs, rhs) => Expression::shl(lhs.into_(), rhs.into_()),
            Expression::Shr(lhs, rhs) => Expression::shr(lhs.into_(), rhs.into_()),
            Expression::Cmpeq(lhs, rhs) => Expression::cmpeq(lhs.into_(), rhs.into_()),
            Expression::Cmpneq(lhs, rhs) => Expression::cmpneq(lhs.into_(), rhs.into_()),
            Expression::Cmplts(lhs, rhs) => Expression::cmplts(lhs.into_(), rhs.into_()),
            Expression::Cmpltu(lhs, rhs) => Expression::cmpltu(lhs.into_(), rhs.into_()),
            Expression::Zext(bits, rhs) => Expression::zext(bits, rhs.into_()),
            Expression::Sext(bits, rhs) => Expression::sext(bits, rhs.into_()),
            Expression::Trun(bits, rhs) => Expression::trun(bits, rhs.into_()),
        }
    }
}



/// An abstract state, which holds the values of all variables and a memory
/// model.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State<M: Memory<V>, V: Value> {
    pub(crate) variables: HashMap<il::Scalar, V>,
    pub(crate) memory: M
}


impl<M: Memory<V>, V: Value> PartialOrd for State<M, V> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        let mut ordering = Ordering::Equal;

        for self_variable in &self.variables {
            let variable_ordering = match other.variables.get(self_variable.0) {
                Some(ref other_variable) => match self_variable.1.partial_cmp(other_variable) {
                    Some(variable_ordering) => variable_ordering,
                    None => { return None; }
                },
                None => Ordering::Greater
            };
            ordering =
                if variable_ordering == Ordering::Equal {
                    ordering
                }
                else if ordering == Ordering::Equal || ordering == variable_ordering {
                    variable_ordering
                }
                else {
                    return None;
                };
        }

        for other_variable in &other.variables {
            if self.variables.get(other_variable.0).is_none() {
                ordering =
                    if ordering == Ordering::Greater {
                        return None;
                    }
                    else {
                        Ordering::Less
                    };
            }
        }

        match self.memory.partial_cmp(&other.memory) {
            Some(memory_ordering) =>
                if memory_ordering == Ordering::Equal {
                    Some(ordering)
                }
                else if ordering == Ordering::Equal || ordering == memory_ordering {
                    Some(memory_ordering)
                }
                else {
                    None
                },
            None => {
                None
            }
        }
    }
}


impl<M: Memory<V>, V: Value> PartialEq for State<M, V> {
    fn eq(&self, other: &Self) -> bool {
        match self.partial_cmp(other) {
            Some(ordering) => match ordering {
                Ordering::Equal => true,
                _ => false
            },
            None => false
        }
    }
}


impl<M, V> State<M, V> where M: Memory<V>, V: Value {
    /// Retrieve the variables tied to this `State`
    pub fn variables(&self) -> &HashMap<il::Scalar, V> {
        &self.variables
    }

    /// Retrieve the memory model tied to this `State`
    pub fn memory(&self) -> &M {
        &self.memory
    }

    /// Retrieve a mutable reference to the memory model tied to this `State`
    pub fn memory_mut(&mut self) -> &mut M {
        &mut self.memory
    }
}


impl<M, V> State<M, V> where M: Memory<V>, V: Value {
    /// Create a new `State` with no variables and the given `Memory`
    pub fn new(memory: M) -> State<M, V> {
        State {
            variables: HashMap::new(),
            memory: memory
        }
    }

    /// Retrieve the abstract `Value` associated with the given `Scalar`
    pub fn variable(&self, key: &il::Scalar) -> Option<&V> {
        self.variables.get(key)
    }

    /// Set the value associated with `Scalar` to an abstract `Value` in this
    /// state
    pub fn set_variable(&mut self, key: il::Scalar, value: V) {
        self.variables.insert(key, value);
    }

    /// Remove a variable from this state. Returns true if the variable was
    /// present in this state.
    pub fn remove_variable(&mut self, key: &il::Scalar) {
        self.variables.remove(key);
    }

    /// Join this abstract state with another abstract state.
    pub fn join(mut self, other: &Self) -> Result<Self> {
        for variable in &other.variables {
            let v = match self.variables.get(variable.0) {
                Some (v) => v.join(variable.1)?,
                None => variable.1.clone()
            };
            self.variables.insert(variable.0.clone(), v);
        }
        self.memory = Memory::join(self.memory, &other.memory)?;
        Ok(self)
    }

    /// Replace scalars in the given `il::Expression` with the values held in this
    /// state.
    pub fn symbolize(&self, expression: &il::Expression) -> Expression<V> {

        match *expression {
            il::Expression::Scalar(ref scalar) => {
                match self.variable(scalar) {
                    Some(v) => {
                        Expression::value(v.clone())
                    },
                    None => Expression::value(V::top(scalar.bits()))
                }
            },
            il::Expression::Constant(ref constant) =>
                Expression::value(V::constant(constant.clone())),
            il::Expression::Add(ref lhs, ref rhs) =>
                Expression::add(self.symbolize(lhs), self.symbolize(rhs)),
            il::Expression::Sub(ref lhs, ref rhs) =>
                Expression::sub(self.symbolize(lhs), self.symbolize(rhs)),
            il::Expression::Mul(ref lhs, ref rhs) =>
                Expression::mul(self.symbolize(lhs), self.symbolize(rhs)),
            il::Expression::Divu(ref lhs, ref rhs) =>
                Expression::divu(self.symbolize(lhs), self.symbolize(rhs)),
            il::Expression::Modu(ref lhs, ref rhs) =>
                Expression::modu(self.symbolize(lhs), self.symbolize(rhs)),
            il::Expression::Divs(ref lhs, ref rhs) =>
                Expression::divs(self.symbolize(lhs), self.symbolize(rhs)),
            il::Expression::Mods(ref lhs, ref rhs) =>
                Expression::mods(self.symbolize(lhs), self.symbolize(rhs)),
            il::Expression::And(ref lhs, ref rhs) =>
                Expression::and(self.symbolize(lhs), self.symbolize(rhs)),
            il::Expression::Or(ref lhs, ref rhs) =>
                Expression::or(self.symbolize(lhs), self.symbolize(rhs)),
            il::Expression::Xor(ref lhs, ref rhs) =>
                Expression::xor(self.symbolize(lhs), self.symbolize(rhs)),
            il::Expression::Shl(ref lhs, ref rhs) =>
                Expression::shl(self.symbolize(lhs), self.symbolize(rhs)),
            il::Expression::Shr(ref lhs, ref rhs) =>
                Expression::shr(self.symbolize(lhs), self.symbolize(rhs)),
            il::Expression::Cmpeq(ref lhs, ref rhs) =>
                Expression::cmpeq(self.symbolize(lhs), self.symbolize(rhs)),
            il::Expression::Cmpneq(ref lhs, ref rhs) =>
                Expression::cmpneq(self.symbolize(lhs), self.symbolize(rhs)),
            il::Expression::Cmpltu(ref lhs, ref rhs) =>
                Expression::cmpltu(self.symbolize(lhs), self.symbolize(rhs)),
            il::Expression::Cmplts(ref lhs, ref rhs) =>
                Expression::cmplts(self.symbolize(lhs), self.symbolize(rhs)),
            il::Expression::Zext(bits, ref rhs) =>
                Expression::zext(bits, self.symbolize(rhs)),
            il::Expression::Sext(bits, ref rhs) =>
                Expression::sext(bits, self.symbolize(rhs)),
            il::Expression::Trun(bits, ref rhs) =>
                Expression::trun(bits, self.symbolize(rhs))
        }
    }
}


#[test]
fn symbolize() {
    use analysis::ai::test_lattice::*;
    use analysis::ai;
    use types::Endian;

    let memory = ai::memory::Memory::new(Endian::Big);
    let mut state: TestLatticeState = State::new(memory);

    state.set_variable(il::scalar("$a0", 32),
                       TestLattice::Constant(il::const_(0x570000, 32)));

    let expr = il::Expression::add(il::scalar("$a0", 32).into(), 
                                   il::const_(0x703c, 32).into()).unwrap();
    let expr = state.symbolize(&expr);

    let result = TestLattice::eval(&expr).unwrap();

    assert_eq!(result, TestLattice::Constant(il::const_(0x57703c, 32)));
}

#[cfg(test)]
mod test_lattice {
    use analysis::ai::domain;
    use analysis::ai::memory;
    use analysis::ai::test_lattice::*;
    use il;
    use std::cmp::{Ordering, PartialOrd};
    use types::Endian;

    type TestMemory<'m> = memory::Memory<'m, TestLattice>;
    type TestState<'m> = domain::State<TestMemory<'m>, TestLattice>;

    #[test]
    fn ordering() {
        let blank_memory = TestMemory::new(Endian::Big);
        let mut state0 = TestState::new(blank_memory.clone());
        let mut state1 = TestState::new(blank_memory.clone());

        assert_eq!(state0.partial_cmp(&state1), Some(Ordering::Equal));

        let test_constant = TestLattice::Constant(il::const_(0xdeadbeef, 32));
        state0.set_variable(il::scalar("test", 32), test_constant.clone());

        assert!(state0 > state1);

        state1.set_variable(il::scalar("test", 32), test_constant.clone());

        assert!(state0 == state1);

        state0.set_variable(il::scalar("test", 32), TestLattice::Top(32));

        assert!(state0 > state1);

        state1.set_variable(il::scalar("blah", 32), TestLattice::Top(32));

        assert!(!(state0 >= state1));

        state1 = state0.clone();

        state0.memory_mut().store(0x100, test_constant.clone()).unwrap();

        assert_eq!(state0.partial_cmp(&state1), Some(Ordering::Less));

        state1.memory_mut().store(0x100, test_constant.clone()).unwrap();

        assert_eq!(state0.partial_cmp(&state1), Some(Ordering::Equal));

        state1.memory_mut().store(0x100,
            TestLattice::Constant(il::const_(0, 32))).unwrap();
        
        assert_eq!(state0.memory().load(0x100, 32).unwrap(), test_constant);
        assert_eq!(state1.memory().load(0x100, 32).unwrap(),
            TestLattice::Constant(il::const_(0, 32)));
        assert_eq!(state1.memory().load(0x100, 8).unwrap(),
            TestLattice::Constant(il::const_(0, 8)));

        assert_eq!(state0.partial_cmp(&state1), None);
    }
}