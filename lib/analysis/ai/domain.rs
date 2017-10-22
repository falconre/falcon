use error::*;
use il;
use serde::Serialize;
use std::collections::{HashMap};
use std::fmt::{Debug, Display};
use types::Endian;


pub trait Value: Clone + Display + Debug + Eq + PartialEq + Serialize {
    /// Join this abstract value with another
    fn join(&self, other: &Self) -> Result<Self>;

    /// Return an empty/bottom abstract value
    fn empty(bits: usize) -> Self;

    /// Take an il::Constant, and turn it into an abstract value
    fn constant(constant: il::Constant) -> Self; 
}


pub trait Memory<V: Value>: Clone + Debug + Eq + PartialEq + Serialize {
    fn store(&mut self, index: &V, value: V) -> Result<()>;
    fn load(&self, index: &V, bits: usize) -> Result<V>;
    fn new(endian: Endian) -> Self;
    fn join(self, other: &Self) -> Result<Self>;
}


pub trait Domain<M: Memory<V>, V: Value> {
    /// Evaluate an expression of abstract values
    fn eval(&self, expr: &Expression<V>) -> Result<V>;

    /// Handle a brc operation
    fn brc(&self, target: &V, condition: &V, state: State<M, V>) -> Result<State<M, V>>;

    /// Handle a raise operation
    fn raise(&self, expr: &V, state: State<M, V>) -> Result<State<M, V>>;

    /// Return the endianness used for analysis
    fn endian(&self) -> Endian;

    /// Return an empty state
    fn new_state(&self) -> State<M, V>;
}


pub enum Expression<V: Value> {
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


impl<V> Expression<V> where V: Value {
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
}


#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State<M: Memory<V>, V: Value> {
    pub(crate) variables: HashMap<il::Scalar, V>,
    pub(crate) memory: M
}


impl<M, V> State<M, V> where M: Memory<V>, V: Value {
    pub fn variables(&self) -> &HashMap<il::Scalar, V> {
        &self.variables
    }

    pub fn memory(&self) -> &M {
        &self.memory
    }
}


impl<M, V> State<M, V> where M: Memory<V>, V: Value {
    pub fn new(memory: M) -> State<M, V> {
        State {
            variables: HashMap::new(),
            memory: memory
        }
    }


    pub fn variable(&self, key: &il::Scalar) -> Option<&V> {
        self.variables.get(key)
    }


    pub fn set_variable(&mut self, key: il::Scalar, value: V) {
        self.variables.insert(key, value);
    }


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
}