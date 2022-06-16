//! A concrete state for execution over Falcon IL.

use std::collections::BTreeMap;

use crate::executor::successor::*;
use crate::executor::*;

/// A concrete `State`.
#[derive(Debug, Clone)]
pub struct State {
    scalars: BTreeMap<String, il::Constant>,
    memory: Memory,
}

impl State {
    /// Create a new `State` from the given memory model.
    pub fn new(memory: Memory) -> State {
        State {
            scalars: BTreeMap::new(),
            memory,
        }
    }

    /// Retrieve the `Memory` associated with this `State`.
    pub fn memory(&self) -> &Memory {
        &self.memory
    }

    /// Retrieve a mutable reference to the `Memory` associated with this
    /// `State`.
    pub fn memory_mut(&mut self) -> &mut Memory {
        &mut self.memory
    }

    /// Set the value of the given scalar to a concrete value.
    pub fn set_scalar<S: Into<String>>(&mut self, name: S, value: il::Constant) {
        self.scalars.insert(name.into(), value);
    }

    /// Get the concrete value of the given scalar.
    pub fn get_scalar(&self, name: &str) -> Option<&il::Constant> {
        self.scalars.get(name)
    }

    /// Symbolize an expression, replacing all scalars with the concrete values
    /// stored in this state.
    pub fn symbolize_expression(
        &self,
        expression: &il::Expression,
    ) -> Result<il::Expression, Error> {
        Ok(match *expression {
            il::Expression::Scalar(ref scalar) => match self.scalars.get(scalar.name()) {
                Some(expr) => expr.clone().into(),
                None => il::Expression::Scalar(scalar.clone()),
            },
            il::Expression::Constant(_) => expression.clone(),
            il::Expression::Add(ref lhs, ref rhs) => il::Expression::add(
                self.symbolize_expression(lhs)?,
                self.symbolize_expression(rhs)?,
            )?,
            il::Expression::Sub(ref lhs, ref rhs) => il::Expression::sub(
                self.symbolize_expression(lhs)?,
                self.symbolize_expression(rhs)?,
            )?,
            il::Expression::Mul(ref lhs, ref rhs) => il::Expression::mul(
                self.symbolize_expression(lhs)?,
                self.symbolize_expression(rhs)?,
            )?,
            il::Expression::Divu(ref lhs, ref rhs) => il::Expression::divu(
                self.symbolize_expression(lhs)?,
                self.symbolize_expression(rhs)?,
            )?,
            il::Expression::Modu(ref lhs, ref rhs) => il::Expression::modu(
                self.symbolize_expression(lhs)?,
                self.symbolize_expression(rhs)?,
            )?,
            il::Expression::Divs(ref lhs, ref rhs) => il::Expression::divs(
                self.symbolize_expression(lhs)?,
                self.symbolize_expression(rhs)?,
            )?,
            il::Expression::Mods(ref lhs, ref rhs) => il::Expression::mods(
                self.symbolize_expression(lhs)?,
                self.symbolize_expression(rhs)?,
            )?,
            il::Expression::And(ref lhs, ref rhs) => il::Expression::and(
                self.symbolize_expression(lhs)?,
                self.symbolize_expression(rhs)?,
            )?,
            il::Expression::Or(ref lhs, ref rhs) => il::Expression::or(
                self.symbolize_expression(lhs)?,
                self.symbolize_expression(rhs)?,
            )?,
            il::Expression::Xor(ref lhs, ref rhs) => il::Expression::xor(
                self.symbolize_expression(lhs)?,
                self.symbolize_expression(rhs)?,
            )?,
            il::Expression::Shl(ref lhs, ref rhs) => il::Expression::shl(
                self.symbolize_expression(lhs)?,
                self.symbolize_expression(rhs)?,
            )?,
            il::Expression::Shr(ref lhs, ref rhs) => il::Expression::shr(
                self.symbolize_expression(lhs)?,
                self.symbolize_expression(rhs)?,
            )?,
            #[cfg(feature = "il-expression-ashr")]
            il::Expression::AShr(ref lhs, ref rhs) => il::Expression::ashr(
                self.symbolize_expression(lhs)?,
                self.symbolize_expression(rhs)?,
            )?,
            il::Expression::Cmpeq(ref lhs, ref rhs) => il::Expression::cmpeq(
                self.symbolize_expression(lhs)?,
                self.symbolize_expression(rhs)?,
            )?,
            il::Expression::Cmpneq(ref lhs, ref rhs) => il::Expression::cmpneq(
                self.symbolize_expression(lhs)?,
                self.symbolize_expression(rhs)?,
            )?,
            il::Expression::Cmplts(ref lhs, ref rhs) => il::Expression::cmplts(
                self.symbolize_expression(lhs)?,
                self.symbolize_expression(rhs)?,
            )?,
            il::Expression::Cmpltu(ref lhs, ref rhs) => il::Expression::cmpltu(
                self.symbolize_expression(lhs)?,
                self.symbolize_expression(rhs)?,
            )?,
            il::Expression::Zext(bits, ref src) => {
                il::Expression::zext(bits, self.symbolize_expression(src)?)?
            }
            il::Expression::Sext(bits, ref src) => {
                il::Expression::sext(bits, self.symbolize_expression(src)?)?
            }
            il::Expression::Trun(bits, ref src) => {
                il::Expression::trun(bits, self.symbolize_expression(src)?)?
            }
            il::Expression::Ite(ref cond, ref then, ref else_) => il::Expression::ite(
                self.symbolize_expression(cond)?,
                self.symbolize_expression(then)?,
                self.symbolize_expression(else_)?,
            )?,
        })
    }

    /// Symbolize the given expression, replacing all scalars with the concrete
    /// values held in this state, and evaluate the expression to a single
    /// concrete value.
    pub fn symbolize_and_eval(&self, expression: &il::Expression) -> Result<il::Constant, Error> {
        let expression = self.symbolize_expression(expression)?;
        eval(&expression)
    }

    /// Execute an `il::Operation`, returning the post-execution `State`.
    pub fn execute(mut self, operation: &il::Operation) -> Result<Successor, Error> {
        match *operation {
            il::Operation::Assign { ref dst, ref src } => {
                let src = self.symbolize_and_eval(src)?;
                self.set_scalar(dst.name(), src);
                Ok(Successor::new(self, SuccessorType::FallThrough))
            }
            il::Operation::Store { ref index, ref src } => {
                let src = self.symbolize_and_eval(src)?;
                let index = self.symbolize_and_eval(index)?;
                self.memory
                    .store(index.value_u64().ok_or(Error::TooManyAddressBits)?, src)?;
                Ok(Successor::new(self, SuccessorType::FallThrough))
            }
            il::Operation::Load { ref dst, ref index } => {
                let index = self.symbolize_and_eval(index)?;
                let value = self.memory.load(
                    index.value_u64().ok_or(Error::TooManyAddressBits)?,
                    dst.bits(),
                )?;
                match value {
                    Some(v) => {
                        self.set_scalar(dst.name(), v);
                        Ok(Successor::new(self, SuccessorType::FallThrough))
                    }
                    None => Err(Error::ExecutorInvalidAddress),
                }
            }
            il::Operation::Branch { ref target } => {
                let target = self.symbolize_and_eval(target)?;
                Ok(Successor::new(
                    self,
                    SuccessorType::Branch(target.value_u64().ok_or(Error::TooManyAddressBits)?),
                ))
            }
            il::Operation::Intrinsic { ref intrinsic } => {
                Err(Error::UnhandledIntrinsic(format!("{}", intrinsic)))
            }
            il::Operation::Nop { .. } => Ok(Successor::new(self, SuccessorType::FallThrough)),
        }
    }
}

impl From<Successor> for State {
    fn from(successor: Successor) -> State {
        successor.state
    }
}
