//! An `Expression`.
//!
//! # Expression Rules
//! ## Bitness
//! We refer to the number of bits in the result of an `Expression` as its _bitness_.
//!
//! Expressions must always have the same bitness. For example, you cannot add an 8-bit and a
//! 16-bit expression. You must extern or truncate one of these operands until the bitness
//! matches. The bitness of all comparison expressions is always 1.
//!
//! # Expression Breakdown
//! ## Terminals
//! `scalar`, `constant`
//!
//! ## Binary Arithmetic
//! `add`, `sub`, `divu`, `modu`, `divs`, `mods`, `and`, `or`, `xor`, `shl`, `shr`
//!
//! ## Comparison
//! `cmpeq`, `cmpneq`, `cmplts`, `cmpltu`
//!
//! ## Extension/Truncation
//! `zext`, `sext`, `trun`

use std::fmt;

use crate::il::*;
use crate::Error;
use serde::{Deserialize, Serialize};

/// An IL Expression.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub enum Expression {
    Scalar(Scalar),
    Constant(Constant),

    Add(Box<Expression>, Box<Expression>),
    Sub(Box<Expression>, Box<Expression>),
    Mul(Box<Expression>, Box<Expression>),
    Divu(Box<Expression>, Box<Expression>),
    Modu(Box<Expression>, Box<Expression>),
    Divs(Box<Expression>, Box<Expression>),
    Mods(Box<Expression>, Box<Expression>),
    And(Box<Expression>, Box<Expression>),
    Or(Box<Expression>, Box<Expression>),
    Xor(Box<Expression>, Box<Expression>),
    Shl(Box<Expression>, Box<Expression>),
    Shr(Box<Expression>, Box<Expression>),
    #[cfg(feature = "il-expression-ashr")]
    AShr(Box<Expression>, Box<Expression>),

    Cmpeq(Box<Expression>, Box<Expression>),
    Cmpneq(Box<Expression>, Box<Expression>),
    Cmplts(Box<Expression>, Box<Expression>),
    Cmpltu(Box<Expression>, Box<Expression>),

    Zext(usize, Box<Expression>),
    Sext(usize, Box<Expression>),
    Trun(usize, Box<Expression>),

    Ite(Box<Expression>, Box<Expression>, Box<Expression>),
}

impl Expression {
    /// Return the bitness of this expression.
    pub fn bits(&self) -> usize {
        match *self {
            Expression::Scalar(ref scalar) => scalar.bits(),
            Expression::Constant(ref constant) => constant.bits(),
            Expression::Add(ref lhs, _)
            | Expression::Sub(ref lhs, _)
            | Expression::Mul(ref lhs, _)
            | Expression::Divu(ref lhs, _)
            | Expression::Modu(ref lhs, _)
            | Expression::Divs(ref lhs, _)
            | Expression::Mods(ref lhs, _)
            | Expression::And(ref lhs, _)
            | Expression::Or(ref lhs, _)
            | Expression::Xor(ref lhs, _)
            | Expression::Shl(ref lhs, _)
            | Expression::Shr(ref lhs, _) => lhs.bits(),
            #[cfg(feature = "il-expression-ashr")]
            Expression::AShr(ref lhs, _) => lhs.bits(),
            Expression::Cmpeq(_, _)
            | Expression::Cmpneq(_, _)
            | Expression::Cmplts(_, _)
            | Expression::Cmpltu(_, _) => 1,
            Expression::Zext(bits, _) | Expression::Sext(bits, _) | Expression::Trun(bits, _) => {
                bits
            }
            Expression::Ite(_, ref lhs, _) => lhs.bits(),
        }
    }

    /// Ensures the bits of both lhs and rhs are the same.
    fn ensure_sort(lhs: &Expression, rhs: &Expression) -> Result<(), Error> {
        if lhs.bits() != rhs.bits() {
            Err(Error::Sort)
        } else {
            Ok(())
        }
    }

    /// Takes a closure which modifies an existing `Expression`
    ///
    /// The closure takes an expression, and returns an Option<Expression>. If
    /// the option is Some, that value will replace the sub expression in the
    /// larger expression. If closure returns None, the original sub
    /// expression will be used in the larger expression.
    fn map_to_expression<F>(&self, f: F) -> Result<Expression, Error>
    where
        F: Fn(&Expression) -> Option<Expression>,
    {
        struct Map<F> {
            f: F,
        }

        impl<F> Map<F>
        where
            F: Fn(&Expression) -> Option<Expression>,
        {
            fn map(&self, expression: &Expression) -> Result<Expression, Error> {
                Ok(if let Some(expression) = (self.f)(expression) {
                    expression
                } else {
                    match *expression {
                        Expression::Scalar(ref scalar) => scalar.clone().into(),
                        Expression::Constant(ref constant) => constant.clone().into(),
                        Expression::Add(ref lhs, ref rhs) => {
                            Expression::add(self.map(lhs)?, self.map(rhs)?)?
                        }
                        Expression::Sub(ref lhs, ref rhs) => {
                            Expression::sub(self.map(lhs)?, self.map(rhs)?)?
                        }
                        Expression::Mul(ref lhs, ref rhs) => {
                            Expression::mul(self.map(lhs)?, self.map(rhs)?)?
                        }
                        Expression::Divu(ref lhs, ref rhs) => {
                            Expression::divu(self.map(lhs)?, self.map(rhs)?)?
                        }
                        Expression::Modu(ref lhs, ref rhs) => {
                            Expression::modu(self.map(lhs)?, self.map(rhs)?)?
                        }
                        Expression::Divs(ref lhs, ref rhs) => {
                            Expression::divs(self.map(lhs)?, self.map(rhs)?)?
                        }
                        Expression::Mods(ref lhs, ref rhs) => {
                            Expression::mods(self.map(lhs)?, self.map(rhs)?)?
                        }
                        Expression::And(ref lhs, ref rhs) => {
                            Expression::and(self.map(lhs)?, self.map(rhs)?)?
                        }
                        Expression::Or(ref lhs, ref rhs) => {
                            Expression::or(self.map(lhs)?, self.map(rhs)?)?
                        }
                        Expression::Xor(ref lhs, ref rhs) => {
                            Expression::xor(self.map(lhs)?, self.map(rhs)?)?
                        }
                        Expression::Shl(ref lhs, ref rhs) => {
                            Expression::shl(self.map(lhs)?, self.map(rhs)?)?
                        }
                        Expression::Shr(ref lhs, ref rhs) => {
                            Expression::shr(self.map(lhs)?, self.map(rhs)?)?
                        }
                        #[cfg(feature = "il-expression-ashr")]
                        Expression::AShr(ref lhs, ref rhs) => {
                            Expression::ashr(self.map(lhs)?, self.map(rhs)?)?
                        }
                        Expression::Cmpeq(ref lhs, ref rhs) => {
                            Expression::cmpeq(self.map(lhs)?, self.map(rhs)?)?
                        }
                        Expression::Cmpneq(ref lhs, ref rhs) => {
                            Expression::cmpneq(self.map(lhs)?, self.map(rhs)?)?
                        }
                        Expression::Cmpltu(ref lhs, ref rhs) => {
                            Expression::cmpltu(self.map(lhs)?, self.map(rhs)?)?
                        }
                        Expression::Cmplts(ref lhs, ref rhs) => {
                            Expression::cmplts(self.map(lhs)?, self.map(rhs)?)?
                        }
                        Expression::Zext(bits, ref src) => Expression::zext(bits, self.map(src)?)?,
                        Expression::Sext(bits, ref src) => Expression::sext(bits, self.map(src)?)?,
                        Expression::Trun(bits, ref src) => Expression::trun(bits, self.map(src)?)?,
                        Expression::Ite(ref cond, ref then, ref else_) => {
                            Expression::ite(self.map(cond)?, self.map(then)?, self.map(else_)?)?
                        }
                    }
                })
            }
        }

        let map = Map { f };

        map.map(self)
    }

    /// Return a clone of this expression, but with every occurrence of the
    /// given scalar replaced with the given expression
    pub fn replace_scalar(
        &self,
        scalar: &Scalar,
        expression: &Expression,
    ) -> Result<Expression, Error> {
        self.map_to_expression(|expr| {
            if let Expression::Scalar(ref expr_scalar) = *expr {
                if expr_scalar == scalar {
                    Some(expression.clone())
                } else {
                    None
                }
            } else {
                None
            }
        })
    }

    /// Return true if all terminals in this expression are Constant
    pub fn all_constants(&self) -> bool {
        match *self {
            Expression::Scalar(_) => false,
            Expression::Constant(_) => true,
            Expression::Add(ref lhs, ref rhs)
            | Expression::Sub(ref lhs, ref rhs)
            | Expression::Mul(ref lhs, ref rhs)
            | Expression::Divu(ref lhs, ref rhs)
            | Expression::Modu(ref lhs, ref rhs)
            | Expression::Divs(ref lhs, ref rhs)
            | Expression::Mods(ref lhs, ref rhs)
            | Expression::And(ref lhs, ref rhs)
            | Expression::Or(ref lhs, ref rhs)
            | Expression::Xor(ref lhs, ref rhs)
            | Expression::Shl(ref lhs, ref rhs)
            | Expression::Shr(ref lhs, ref rhs)
            | Expression::Cmpeq(ref lhs, ref rhs)
            | Expression::Cmpneq(ref lhs, ref rhs)
            | Expression::Cmplts(ref lhs, ref rhs)
            | Expression::Cmpltu(ref lhs, ref rhs) => lhs.all_constants() && rhs.all_constants(),
            #[cfg(feature = "il-expression-ashr")]
            Expression::AShr(ref lhs, ref rhs) => lhs.all_constants() && rhs.all_constants(),
            Expression::Zext(_, ref rhs)
            | Expression::Sext(_, ref rhs)
            | Expression::Trun(_, ref rhs) => rhs.all_constants(),
            Expression::Ite(ref cond, ref then, ref else_) => {
                cond.all_constants() && then.all_constants() && else_.all_constants()
            }
        }
    }

    /// Returns all `Scalars` used in this `Expression`
    pub fn scalars(&self) -> Vec<&Scalar> {
        let mut scalars: Vec<&Scalar> = Vec::new();
        match *self {
            Expression::Scalar(ref scalar) => scalars.push(scalar),
            Expression::Constant(_) => {}
            Expression::Add(ref lhs, ref rhs)
            | Expression::Sub(ref lhs, ref rhs)
            | Expression::Mul(ref lhs, ref rhs)
            | Expression::Divu(ref lhs, ref rhs)
            | Expression::Modu(ref lhs, ref rhs)
            | Expression::Divs(ref lhs, ref rhs)
            | Expression::Mods(ref lhs, ref rhs)
            | Expression::And(ref lhs, ref rhs)
            | Expression::Or(ref lhs, ref rhs)
            | Expression::Xor(ref lhs, ref rhs)
            | Expression::Shl(ref lhs, ref rhs)
            | Expression::Shr(ref lhs, ref rhs)
            | Expression::Cmpeq(ref lhs, ref rhs)
            | Expression::Cmpneq(ref lhs, ref rhs)
            | Expression::Cmplts(ref lhs, ref rhs)
            | Expression::Cmpltu(ref lhs, ref rhs) => {
                scalars.append(&mut lhs.scalars());
                scalars.append(&mut rhs.scalars());
            }
            #[cfg(feature = "il-expression-ashr")]
            Expression::AShr(ref lhs, ref rhs) => {
                scalars.append(&mut lhs.scalars());
                scalars.append(&mut rhs.scalars());
            }
            Expression::Zext(_, ref rhs)
            | Expression::Sext(_, ref rhs)
            | Expression::Trun(_, ref rhs) => {
                scalars.append(&mut rhs.scalars());
            }
            Expression::Ite(ref cond, ref then, ref else_) => {
                scalars.append(&mut cond.scalars());
                scalars.append(&mut then.scalars());
                scalars.append(&mut else_.scalars());
            }
        }
        scalars
    }

    /// Return mutable references to all `Scalars` in this `Expression`.
    pub fn scalars_mut(&mut self) -> Vec<&mut Scalar> {
        let mut scalars: Vec<&mut Scalar> = Vec::new();
        match *self {
            Expression::Scalar(ref mut scalar) => scalars.push(scalar),
            Expression::Constant(_) => {}
            Expression::Add(ref mut lhs, ref mut rhs)
            | Expression::Sub(ref mut lhs, ref mut rhs)
            | Expression::Mul(ref mut lhs, ref mut rhs)
            | Expression::Divu(ref mut lhs, ref mut rhs)
            | Expression::Modu(ref mut lhs, ref mut rhs)
            | Expression::Divs(ref mut lhs, ref mut rhs)
            | Expression::Mods(ref mut lhs, ref mut rhs)
            | Expression::And(ref mut lhs, ref mut rhs)
            | Expression::Or(ref mut lhs, ref mut rhs)
            | Expression::Xor(ref mut lhs, ref mut rhs)
            | Expression::Shl(ref mut lhs, ref mut rhs)
            | Expression::Shr(ref mut lhs, ref mut rhs)
            | Expression::Cmpeq(ref mut lhs, ref mut rhs)
            | Expression::Cmpneq(ref mut lhs, ref mut rhs)
            | Expression::Cmplts(ref mut lhs, ref mut rhs)
            | Expression::Cmpltu(ref mut lhs, ref mut rhs) => {
                scalars.append(&mut lhs.scalars_mut());
                scalars.append(&mut rhs.scalars_mut());
            }
            #[cfg(feature = "il-expression-ashr")]
            Expression::AShr(ref mut lhs, ref mut rhs) => {
                scalars.append(&mut lhs.scalars_mut());
                scalars.append(&mut rhs.scalars_mut());
            }
            Expression::Zext(_, ref mut rhs)
            | Expression::Sext(_, ref mut rhs)
            | Expression::Trun(_, ref mut rhs) => {
                scalars.append(&mut rhs.scalars_mut());
            }
            Expression::Ite(ref mut cond, ref mut then, ref mut else_) => {
                scalars.append(&mut cond.scalars_mut());
                scalars.append(&mut then.scalars_mut());
                scalars.append(&mut else_.scalars_mut());
            }
        }
        scalars
    }

    /// If this expression is a scalar, return the scalar
    pub fn get_scalar(&self) -> Option<&Scalar> {
        match *self {
            Expression::Scalar(ref scalar) => Some(scalar),
            _ => None,
        }
    }

    /// If this expression is a constant, return the constant
    pub fn get_constant(&self) -> Option<&Constant> {
        match *self {
            Expression::Constant(ref constant) => Some(constant),
            _ => None,
        }
    }

    /// Create a new `Expression` from a `Scalar`.
    pub fn scalar(scalar: Scalar) -> Expression {
        Expression::Scalar(scalar)
    }

    /// Create a new `Expression` from a `Constant`.
    pub fn constant(constant: Constant) -> Expression {
        Expression::Constant(constant)
    }

    /// Create an addition `Expression`.
    /// # Error
    /// The sort of the lhs and the rhs are not the same
    #[allow(clippy::should_implement_trait)]
    pub fn add(lhs: Expression, rhs: Expression) -> Result<Expression, Error> {
        Expression::ensure_sort(&lhs, &rhs)?;
        Ok(Expression::Add(Box::new(lhs), Box::new(rhs)))
    }

    /// Create a subtraction `Expression`.
    /// # Error
    /// The sort of the lhs and the rhs are not the same.
    #[allow(clippy::should_implement_trait)]
    pub fn sub(lhs: Expression, rhs: Expression) -> Result<Expression, Error> {
        Expression::ensure_sort(&lhs, &rhs)?;
        Ok(Expression::Sub(Box::new(lhs), Box::new(rhs)))
    }

    /// Create an unsigned multiplication `Expression`.
    /// # Error
    /// The sort of the lhs and the rhs are not the same.
    #[allow(clippy::should_implement_trait)]
    pub fn mul(lhs: Expression, rhs: Expression) -> Result<Expression, Error> {
        Expression::ensure_sort(&lhs, &rhs)?;
        Ok(Expression::Mul(Box::new(lhs), Box::new(rhs)))
    }

    /// Create an unsigned division `Expression`.
    /// # Error
    /// The sort of the lhs and the rhs are not the same.
    pub fn divu(lhs: Expression, rhs: Expression) -> Result<Expression, Error> {
        Expression::ensure_sort(&lhs, &rhs)?;
        Ok(Expression::Divu(Box::new(lhs), Box::new(rhs)))
    }

    /// Create an unsigned modulus `Expression`.
    /// # Error
    /// The sort of the lhs and the rhs are not the same.
    pub fn modu(lhs: Expression, rhs: Expression) -> Result<Expression, Error> {
        Expression::ensure_sort(&lhs, &rhs)?;
        Ok(Expression::Modu(Box::new(lhs), Box::new(rhs)))
    }

    /// Create a signed division `Expression`.
    /// # Error
    /// The sort of the lhs and the rhs are not the same.
    pub fn divs(lhs: Expression, rhs: Expression) -> Result<Expression, Error> {
        Expression::ensure_sort(&lhs, &rhs)?;
        Ok(Expression::Divs(Box::new(lhs), Box::new(rhs)))
    }

    /// Create a signed modulus `Expression`.
    /// # Error
    /// The sort of the lhs and the rhs are not the same.
    pub fn mods(lhs: Expression, rhs: Expression) -> Result<Expression, Error> {
        Expression::ensure_sort(&lhs, &rhs)?;
        Ok(Expression::Mods(Box::new(lhs), Box::new(rhs)))
    }

    /// Create a binary and `Expression`.
    /// # Error
    /// The sort of the lhs and the rhs are not the same.
    pub fn and(lhs: Expression, rhs: Expression) -> Result<Expression, Error> {
        Expression::ensure_sort(&lhs, &rhs)?;
        Ok(Expression::And(Box::new(lhs), Box::new(rhs)))
    }

    /// Create a binary or `Expression`.
    /// # Error
    /// The sort of the lhs and the rhs are not the same.
    pub fn or(lhs: Expression, rhs: Expression) -> Result<Expression, Error> {
        Expression::ensure_sort(&lhs, &rhs)?;
        Ok(Expression::Or(Box::new(lhs), Box::new(rhs)))
    }

    /// Create a binary xor `Expression`.
    /// # Error
    /// The sort of the lhs and the rhs are not the same.
    pub fn xor(lhs: Expression, rhs: Expression) -> Result<Expression, Error> {
        Expression::ensure_sort(&lhs, &rhs)?;
        Ok(Expression::Xor(Box::new(lhs), Box::new(rhs)))
    }

    /// Create a logical shift-left `Expression`.
    /// # Error
    /// The sort of the lhs and the rhs are not the same.
    #[allow(clippy::should_implement_trait)]
    pub fn shl(lhs: Expression, rhs: Expression) -> Result<Expression, Error> {
        Expression::ensure_sort(&lhs, &rhs)?;
        Ok(Expression::Shl(Box::new(lhs), Box::new(rhs)))
    }

    /// Create a logical shift-right `Expression`.
    /// # Error
    /// The sort of the lhs and the rhs are not the same.
    #[allow(clippy::should_implement_trait)]
    pub fn shr(lhs: Expression, rhs: Expression) -> Result<Expression, Error> {
        Expression::ensure_sort(&lhs, &rhs)?;
        Ok(Expression::Shr(Box::new(lhs), Box::new(rhs)))
    }

    /// Create an arithmetic shift-right `Expression`.
    /// # Error
    /// The sort of the lhs and the rhs are not the same.
    #[allow(clippy::should_implement_trait)]
    #[cfg(feature = "il-expression-ashr")]
    pub fn ashr(lhs: Expression, rhs: Expression) -> Result<Expression, Error> {
        Expression::ensure_sort(&lhs, &rhs)?;
        Ok(Expression::AShr(Box::new(lhs), Box::new(rhs)))
    }

    /// Create an arithmetic shift-right `Expression`.
    /// # Error
    /// The sort of the lhs and the rhs are not the same.
    #[allow(clippy::should_implement_trait)]
    #[cfg(not(feature = "il-expression-ashr"))]
    pub fn ashr(lhs: Expression, rhs: Expression) -> Result<Expression, Error> {
        Expression::ensure_sort(&lhs, &rhs)?;

        // Create the mask we apply if that lhs is signed
        let mask = Expression::shl(expr_const(1, lhs.bits()), rhs.clone())?;
        let mask = Expression::sub(mask, expr_const(1, lhs.bits()))?;
        let mask = Expression::shl(
            mask,
            Expression::sub(expr_const(lhs.bits() as u64, lhs.bits()), rhs.clone())?,
        )?;

        // Multiple the mask by the sign bit
        let expr = Expression::shr(lhs.clone(), expr_const(lhs.bits() as u64 - 1, lhs.bits()))?;
        let expr = Expression::mul(mask, expr)?;

        Expression::or(expr, Expression::shr(lhs, rhs)?)
    }

    /// Create an equals comparison `Expression`.
    /// # Error
    /// The sort of the lhs and the rhs are not the same.
    pub fn cmpeq(lhs: Expression, rhs: Expression) -> Result<Expression, Error> {
        Expression::ensure_sort(&lhs, &rhs)?;
        Ok(Expression::Cmpeq(Box::new(lhs), Box::new(rhs)))
    }

    /// Create an not equals comparison `Expression`.
    /// # Error
    /// The sort of the lhs and the rhs are not the same.
    pub fn cmpneq(lhs: Expression, rhs: Expression) -> Result<Expression, Error> {
        Expression::ensure_sort(&lhs, &rhs)?;
        Ok(Expression::Cmpneq(Box::new(lhs), Box::new(rhs)))
    }

    /// Create an unsigned less-than comparison `Expression`.
    /// # Error
    /// The sort of the lhs and the rhs are not the same.
    pub fn cmpltu(lhs: Expression, rhs: Expression) -> Result<Expression, Error> {
        Expression::ensure_sort(&lhs, &rhs)?;
        Ok(Expression::Cmpltu(Box::new(lhs), Box::new(rhs)))
    }

    /// Create a signed less-than comparison `Expression`.
    /// # Error
    /// The sort of the lhs and the rhs are not the same.
    pub fn cmplts(lhs: Expression, rhs: Expression) -> Result<Expression, Error> {
        Expression::ensure_sort(&lhs, &rhs)?;
        Ok(Expression::Cmplts(Box::new(lhs), Box::new(rhs)))
    }

    /// Create an expression to zero-extend src to the number of bits specified
    /// in bits.
    /// # Error
    /// src has more or equal number of bits than bits
    pub fn zext(bits: usize, src: Expression) -> Result<Expression, Error> {
        if src.bits() >= bits || src.bits() == 0 {
            return Err(Error::Sort);
        }
        Ok(Expression::Zext(bits, Box::new(src)))
    }

    /// Create an expression to sign-extend src to the number of bits specified
    /// # Error
    /// src has more or equal number of bits than bits
    pub fn sext(bits: usize, src: Expression) -> Result<Expression, Error> {
        if src.bits() >= bits || src.bits() == 0 {
            return Err(Error::Sort);
        }
        Ok(Expression::Sext(bits, Box::new(src)))
    }

    /// Create an expression to truncate the number of bits in src to the number
    /// of bits given.
    /// # Error
    /// src has less-than or equal bits than bits
    pub fn trun(bits: usize, src: Expression) -> Result<Expression, Error> {
        if src.bits() <= bits || src.bits() == 0 {
            return Err(Error::Sort);
        }
        Ok(Expression::Trun(bits, Box::new(src)))
    }

    /// Create an if-than-else expression
    /// # Error
    /// condition is not 1-bit, or bitness of then and else_ do not match.
    pub fn ite(cond: Expression, then: Expression, else_: Expression) -> Result<Expression, Error> {
        if cond.bits() != 1 || (then.bits() != else_.bits()) {
            return Err(Error::Sort);
        }
        Ok(Expression::Ite(
            Box::new(cond),
            Box::new(then),
            Box::new(else_),
        ))
    }

    /// Perform a shift-right arithmetic
    ///
    /// This is a pseudo-expression, and emits an expression with
    /// sub-expressions
    pub fn sra(lhs: Expression, rhs: Expression) -> Result<Expression, Error> {
        if lhs.bits() != rhs.bits() {
            return Err(Error::Sort);
        }

        let expr = Expression::shr(lhs.clone(), rhs.clone())?;

        let mask = if rhs.bits() <= 64 {
            Expression::shl(
                expr_const(0xffff_ffff_ffff_ffff, rhs.bits()),
                Expression::sub(expr_const(rhs.bits() as u64, rhs.bits()), rhs)?,
            )?
        } else {
            Expression::shl(
                const_(0, rhs.bits()).sub(&const_(1, rhs.bits()))?.into(),
                Expression::sub(expr_const(rhs.bits() as u64, rhs.bits()), rhs)?,
            )?
        };

        Expression::or(
            expr,
            Expression::ite(
                Expression::cmplts(lhs.clone(), expr_const(0, lhs.bits()))?,
                mask,
                expr_const(0, lhs.bits()),
            )?,
        )
    }

    /// Perform a left-rotation
    ///
    /// This is a pseudo-expression, and emits an expression with
    /// sub-expressions
    pub fn rotl(e: Expression, s: Expression) -> Result<Expression, Error> {
        Expression::or(
            Expression::shl(e.clone(), s.clone())?,
            Expression::shr(
                e.clone(),
                Expression::sub(expr_const(e.bits() as u64, e.bits()), s)?,
            )?,
        )
    }
}

impl From<Scalar> for Expression {
    fn from(scalar: Scalar) -> Expression {
        Expression::Scalar(scalar)
    }
}

impl From<Constant> for Expression {
    fn from(constant: Constant) -> Expression {
        Expression::Constant(constant)
    }
}

impl fmt::Display for Expression {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Expression::Scalar(ref s) => s.fmt(f),
            Expression::Constant(ref c) => c.fmt(f),
            Expression::Add(ref lhs, ref rhs) => write!(f, "({} + {})", lhs, rhs),
            Expression::Sub(ref lhs, ref rhs) => write!(f, "({} - {})", lhs, rhs),
            Expression::Mul(ref lhs, ref rhs) => write!(f, "({} * {})", lhs, rhs),
            Expression::Divu(ref lhs, ref rhs) => write!(f, "({} /u {})", lhs, rhs),
            Expression::Modu(ref lhs, ref rhs) => write!(f, "({} %u {})", lhs, rhs),
            Expression::Divs(ref lhs, ref rhs) => write!(f, "({} /s {})", lhs, rhs),
            Expression::Mods(ref lhs, ref rhs) => write!(f, "({} %s {})", lhs, rhs),
            Expression::And(ref lhs, ref rhs) => write!(f, "({} & {})", lhs, rhs),
            Expression::Or(ref lhs, ref rhs) => write!(f, "({} | {})", lhs, rhs),
            Expression::Xor(ref lhs, ref rhs) => write!(f, "({} ^ {})", lhs, rhs),
            Expression::Shl(ref lhs, ref rhs) => write!(f, "({} << {})", lhs, rhs),
            Expression::Shr(ref lhs, ref rhs) => write!(f, "({} >> {})", lhs, rhs),
            #[cfg(feature = "il-expression-ashr")]
            Expression::AShr(ref lhs, ref rhs) => write!(f, "({} >>> {})", lhs, rhs),
            Expression::Cmpeq(ref lhs, ref rhs) => write!(f, "({} == {})", lhs, rhs),
            Expression::Cmpneq(ref lhs, ref rhs) => write!(f, "({} != {})", lhs, rhs),
            Expression::Cmplts(ref lhs, ref rhs) => write!(f, "({} <s {})", lhs, rhs),
            Expression::Cmpltu(ref lhs, ref rhs) => write!(f, "({} <u {})", lhs, rhs),
            Expression::Zext(ref bits, ref src) => write!(f, "zext.{}({})", bits, src),
            Expression::Sext(ref bits, ref src) => write!(f, "sext.{}({})", bits, src),
            Expression::Trun(ref bits, ref src) => write!(f, "trun.{}({})", bits, src),
            Expression::Ite(ref cond, ref then, ref else_) => {
                write!(f, "ite({}, {}, {})", cond, then, else_)
            }
        }
    }
}

#[test]
fn expression_tests() {
    let expression = Expression::add(
        expr_scalar("a", 32),
        Expression::sub(expr_scalar("b", 32), expr_const(0xdeadbeef, 32)).unwrap(),
    )
    .unwrap();

    assert!(expression.scalars().contains(&&scalar("a", 32)));
    assert!(expression.scalars().contains(&&scalar("b", 32)));

    assert!(expression
        .replace_scalar(&scalar("a", 32), &expr_scalar("c", 32))
        .unwrap()
        .scalars()
        .contains(&&scalar("c", 32)));

    assert!(!expression
        .replace_scalar(&scalar("a", 32), &expr_scalar("c", 32))
        .unwrap()
        .scalars()
        .contains(&&scalar("a", 32)));

    assert_eq!(expression.bits(), 32);

    assert!(!expression.all_constants());
}
