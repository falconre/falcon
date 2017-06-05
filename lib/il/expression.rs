use std::fmt;

use il::*;
/// An IL Expression.
/// Expressions form the building blocks of instructions, and always evaluate
/// some value.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub enum Expression {
    Constant(Constant),
    Scalar(Scalar),

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

    Cmpeq(Box<Expression>, Box<Expression>),
    Cmpneq(Box<Expression>, Box<Expression>),
    Cmplts(Box<Expression>, Box<Expression>),
    Cmpltu(Box<Expression>, Box<Expression>),

    Zext(usize, Box<Expression>),
    Sext(usize, Box<Expression>),
    Trun(usize, Box<Expression>),
}


impl Expression {
    /// Return the bit-sort of this expression.
    pub fn bits(&self) -> usize {
        match self {
            &Expression::Scalar(ref scalar) => scalar.bits(),
            &Expression::Constant(ref constant) => constant.bits(),
            &Expression::Add(ref lhs, _) => lhs.bits(),
            &Expression::Sub(ref lhs, _) => lhs.bits(),
            &Expression::Mul(ref lhs, _) => lhs.bits(),
            &Expression::Divu(ref lhs, _) => lhs.bits(),
            &Expression::Modu(ref lhs, _) => lhs.bits(),
            &Expression::Divs(ref lhs, _) => lhs.bits(),
            &Expression::Mods(ref lhs, _) => lhs.bits(),
            &Expression::And(ref lhs, _) => lhs.bits(),
            &Expression::Or(ref lhs, _) => lhs.bits(),
            &Expression::Xor(ref lhs, _) => lhs.bits(),
            &Expression::Shl(ref lhs, _) => lhs.bits(),
            &Expression::Shr(ref lhs, _) => lhs.bits(),
            &Expression::Cmpeq(ref lhs, _) => lhs.bits(),
            &Expression::Cmpneq(ref lhs, _) => lhs.bits(),
            &Expression::Cmplts(ref lhs, _) => lhs.bits(),
            &Expression::Cmpltu(ref lhs, _) => lhs.bits(),
            &Expression::Zext(bits, _) => bits,
            &Expression::Sext(bits, _) => bits,
            &Expression::Trun(bits, _) => bits
        }
    }


    /// Ensures the bits of both lhs and rhs are the same. If no_flags is true,
    /// Also ensures this expression doesn't include flags (which have a sort
    /// of 0)
    fn ensure_sort(lhs: &Expression, rhs: &Expression, no_flags: bool) -> Result<()> {
        if lhs.bits() != rhs.bits() {
            Err(ErrorKind::Sort.into())
        }
        else if no_flags == true && lhs.bits() == 0 {
            Err(ErrorKind::Sort.into())
        }
        else {
            Ok(())
        }
    }

    /// Returns all variables used in the expression
    pub fn collect_scalars(&self) -> Vec<&Scalar> {
        let mut scalars: Vec<&Scalar> = Vec::new();
        match *self {
            Expression::Scalar(ref scalar) => {
                scalars.push(scalar)
            }
            Expression::Constant(_) => {}
            Expression::Add(ref lhs, ref rhs) |
            Expression::Sub(ref lhs, ref rhs) |
            Expression::Mul(ref lhs, ref rhs) |
            Expression::Divu(ref lhs, ref rhs) |
            Expression::Modu(ref lhs, ref rhs) |
            Expression::Divs(ref lhs, ref rhs) |
            Expression::Mods(ref lhs, ref rhs) |
            Expression::And(ref lhs, ref rhs) |
            Expression::Or(ref lhs, ref rhs) |
            Expression::Xor(ref lhs, ref rhs) |
            Expression::Shl(ref lhs, ref rhs) |
            Expression::Shr(ref lhs, ref rhs) |
            Expression::Cmpeq(ref lhs, ref rhs) |
            Expression::Cmpneq(ref lhs, ref rhs) |
            Expression::Cmplts(ref lhs, ref rhs) |
            Expression::Cmpltu(ref lhs, ref rhs) => {
                scalars.append(&mut lhs.collect_scalars());
                scalars.append(&mut rhs.collect_scalars());
            },
            Expression::Zext(_, ref rhs) |
            Expression::Sext(_, ref rhs) |
            Expression::Trun(_, ref rhs) => {
                scalars.append(&mut rhs.collect_scalars());
            }
        }
        scalars
    }

    pub fn collect_scalars_mut(&mut self) -> Vec<&mut Scalar> {
        let mut scalars: Vec<&mut Scalar> = Vec::new();
        match *self {
            Expression::Scalar(ref mut scalar) => {
                scalars.push(scalar)
            }
            Expression::Constant(_) => {}
            Expression::Add(ref mut lhs, ref mut rhs) |
            Expression::Sub(ref mut lhs, ref mut rhs) |
            Expression::Mul(ref mut lhs, ref mut rhs) |
            Expression::Divu(ref mut lhs, ref mut rhs) |
            Expression::Modu(ref mut lhs, ref mut rhs) |
            Expression::Divs(ref mut lhs, ref mut rhs) |
            Expression::Mods(ref mut lhs, ref mut rhs) |
            Expression::And(ref mut lhs, ref mut rhs) |
            Expression::Or(ref mut lhs, ref mut rhs) |
            Expression::Xor(ref mut lhs, ref mut rhs) |
            Expression::Shl(ref mut lhs, ref mut rhs) |
            Expression::Shr(ref mut lhs, ref mut rhs) |
            Expression::Cmpeq(ref mut lhs, ref mut rhs) |
            Expression::Cmpneq(ref mut lhs, ref mut rhs) |
            Expression::Cmplts(ref mut lhs, ref mut rhs) |
            Expression::Cmpltu(ref mut lhs, ref mut rhs) => {
                scalars.append(&mut lhs.collect_scalars_mut());
                scalars.append(&mut rhs.collect_scalars_mut());
            },
            Expression::Zext(_, ref mut rhs) |
            Expression::Sext(_, ref mut rhs) |
            Expression::Trun(_, ref mut rhs) => {
                scalars.append(&mut rhs.collect_scalars_mut());
            }
        }
        scalars
    }

    pub fn collect_variables(&self) -> Vec<&Variable> {
        let mut v: Vec<&Variable> = Vec::new();
        for s in self.collect_scalars() {
            v.push(s);
        }
        v
    }

    pub fn collect_scalar_exprs_mut(&mut self) -> Vec<&mut Expression> {
        let mut scalar_exprs: Vec<&mut Expression> = Vec::new();
        match *self {
            Expression::Scalar(_) => {
                scalar_exprs.push(self)
            },
            Expression::Constant(_) => {},
            Expression::Add(ref mut lhs, ref mut rhs) |
            Expression::Sub(ref mut lhs, ref mut rhs) |
            Expression::Mul(ref mut lhs, ref mut rhs) |
            Expression::Divu(ref mut lhs, ref mut rhs) |
            Expression::Modu(ref mut lhs, ref mut rhs) |
            Expression::Divs(ref mut lhs, ref mut rhs) |
            Expression::Mods(ref mut lhs, ref mut rhs) |
            Expression::And(ref mut lhs, ref mut rhs) |
            Expression::Or(ref mut lhs, ref mut rhs) |
            Expression::Xor(ref mut lhs, ref mut rhs) |
            Expression::Shl(ref mut lhs, ref mut rhs) |
            Expression::Shr(ref mut lhs, ref mut rhs) |
            Expression::Cmpeq(ref mut lhs, ref mut rhs) |
            Expression::Cmpneq(ref mut lhs, ref mut rhs) |
            Expression::Cmplts(ref mut lhs, ref mut rhs) |
            Expression::Cmpltu(ref mut lhs, ref mut rhs) => {
                scalar_exprs.append(&mut lhs.collect_scalar_exprs_mut());
                scalar_exprs.append(&mut rhs.collect_scalar_exprs_mut());
            },
            Expression::Zext(_, ref mut rhs) |
            Expression::Sext(_, ref mut rhs) |
            Expression::Trun(_, ref mut rhs) => {
                scalar_exprs.append(&mut rhs.collect_scalar_exprs_mut());
            }
        }
        scalar_exprs
    }

    /// Create a new expression from a scalar.
    pub fn scalar(scalar: Scalar) -> Expression {
        Expression::Scalar(scalar)
    }

    /// Create a new expression from a constant.
    pub fn constant(constant: Constant) -> Expression {
        Expression::Constant(constant)
    }

    /// Create an addition expression.
    /// # Error
    /// The sort of the lhs and the rhs are not the same
    pub fn add(lhs: Expression, rhs: Expression) -> Result<Expression> {
        try!(Expression::ensure_sort(&lhs, &rhs, true));
        Ok(Expression::Add(Box::new(lhs), Box::new(rhs)))
    }

    /// Create a subtraction expression.
    /// # Error
    /// The sort of the lhs and the rhs are not the same.
    pub fn sub(lhs: Expression, rhs: Expression) -> Result<Expression> {
        try!(Expression::ensure_sort(&lhs, &rhs, true));
        Ok(Expression::Sub(Box::new(lhs), Box::new(rhs)))
    }

    /// Create an unsigned multiplication expression.
    /// # Error
    /// The sort of the lhs and the rhs are not the same.
    pub fn mul(lhs: Expression, rhs: Expression) -> Result<Expression> {
        try!(Expression::ensure_sort(&lhs, &rhs, true));
        Ok(Expression::Mul(Box::new(lhs), Box::new(rhs)))
    }

    /// Create an unsigned division expression.
    /// # Error
    /// The sort of the lhs and the rhs are not the same.
    pub fn divu(lhs: Expression, rhs: Expression) -> Result<Expression> {
        try!(Expression::ensure_sort(&lhs, &rhs, true));
        Ok(Expression::Divu(Box::new(lhs), Box::new(rhs)))
    }

    /// Create an unsigned modulus expression.
    /// # Error
    /// The sort of the lhs and the rhs are not the same.
    pub fn modu(lhs: Expression, rhs: Expression) -> Result<Expression> {
        try!(Expression::ensure_sort(&lhs, &rhs, true));
        Ok(Expression::Modu(Box::new(lhs), Box::new(rhs)))
    }

    /// Create a signed division expression.
    /// # Error
    /// The sort of the lhs and the rhs are not the same.
    pub fn divs(lhs: Expression, rhs: Expression) -> Result<Expression> {
        try!(Expression::ensure_sort(&lhs, &rhs, true));
        Ok(Expression::Divs(Box::new(lhs), Box::new(rhs)))
    }

    /// Create a signed modulus expression.
    /// # Error
    /// The sort of the lhs and the rhs are not the same.
    pub fn mods(lhs: Expression, rhs: Expression) -> Result<Expression> {
        try!(Expression::ensure_sort(&lhs, &rhs, true));
        Ok(Expression::Mods(Box::new(lhs), Box::new(rhs)))
    }

    /// Create a binary and expression.
    /// # Error
    /// The sort of the lhs and the rhs are not the same.
    pub fn and(lhs: Expression, rhs: Expression) -> Result<Expression> {
        try!(Expression::ensure_sort(&lhs, &rhs, true));
        Ok(Expression::And(Box::new(lhs), Box::new(rhs)))
    }

    /// Create a binary or expression.
    /// # Error
    /// The sort of the lhs and the rhs are not the same.
    pub fn or(lhs: Expression, rhs: Expression) -> Result<Expression> {
        try!(Expression::ensure_sort(&lhs, &rhs, true));
        Ok(Expression::Or(Box::new(lhs), Box::new(rhs)))
    }

    /// Create a binary xor expression.
    /// # Error
    /// The sort of the lhs and the rhs are not the same.
    pub fn xor(lhs: Expression, rhs: Expression) -> Result<Expression> {
        try!(Expression::ensure_sort(&lhs, &rhs, true));
        Ok(Expression::Xor(Box::new(lhs), Box::new(rhs)))
    }

    /// Create a logical shift-left expression.
    /// # Error
    /// The sort of the lhs and the rhs are not the same.
    pub fn shl(lhs: Expression, rhs: Expression) -> Result<Expression> {
        try!(Expression::ensure_sort(&lhs, &rhs, true));
        Ok(Expression::Shl(Box::new(lhs), Box::new(rhs)))
    }

    /// Create a logical shift-right expression.
    /// # Error
    /// The sort of the lhs and the rhs are not the same.
    pub fn shr(lhs: Expression, rhs: Expression) -> Result<Expression> {
        try!(Expression::ensure_sort(&lhs, &rhs, true));
        Ok(Expression::Shr(Box::new(lhs), Box::new(rhs)))
    }

    /// Create an equals comparison expression.
    /// # Error
    /// The sort of the lhs and the rhs are not the same.
    pub fn cmpeq(lhs: Expression, rhs: Expression) -> Result<Expression> {
        try!(Expression::ensure_sort(&lhs, &rhs, false));
        Ok(Expression::Cmpeq(Box::new(lhs), Box::new(rhs)))
    }

    /// Create an not equals comparison expression.
    /// # Error
    /// The sort of the lhs and the rhs are not the same.
    pub fn cmpneq(lhs: Expression, rhs: Expression) -> Result<Expression> {
        try!(Expression::ensure_sort(&lhs, &rhs, false));
        Ok(Expression::Cmpneq(Box::new(lhs), Box::new(rhs)))
    }

    /// Create an unsigned less-than comparison expression.
    /// # Error
    /// The sort of the lhs and the rhs are not the same.
    pub fn cmpltu(lhs: Expression, rhs: Expression) -> Result<Expression> {
        try!(Expression::ensure_sort(&lhs, &rhs, false));
        Ok(Expression::Cmpltu(Box::new(lhs), Box::new(rhs)))
    }

    /// Create a signed less-than comparison expression.
    /// # Error
    /// The sort of the lhs and the rhs are not the same.
    pub fn cmplts(lhs: Expression, rhs: Expression) -> Result<Expression> {
        try!(Expression::ensure_sort(&lhs, &rhs, false));
        Ok(Expression::Cmplts(Box::new(lhs), Box::new(rhs)))
    }

    /// Create an expression to zero-extend src to the number of bits specified
    /// in bits.
    /// # Error
    /// src has more or equal number of bits than bits
    pub fn zext(bits: usize, src: Expression) -> Result<Expression> {
        if src.bits() >= bits || src.bits() == 0 {
            return Err(ErrorKind::Sort.into());
        }
        Ok(Expression::Zext(bits, Box::new(src)))
    }

    /// Create an expression to sign-extend src to the number of bits specified
    /// # Error
    /// src has more or equal number of bits than bits
    pub fn sext(bits: usize, src: Expression) -> Result<Expression> {
        if src.bits() >= bits || src.bits() == 0 {
            return Err(ErrorKind::Sort.into());
        }
        Ok(Expression::Sext(bits, Box::new(src)))
    }

    /// Create an expression to truncate the number of bits in src to the number
    /// of bits given.
    /// # Error
    /// src has less-than or equal bits than bits
    pub fn trun(bits: usize, src: Expression) -> Result<Expression> {
        if src.bits() <= bits || src.bits() == 0 {
            return Err(ErrorKind::Sort.into());
        }
        Ok(Expression::Trun(bits, Box::new(src)))
    }
}


impl fmt::Display for Expression {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Expression::Scalar(ref s) => s.fmt(f),
            Expression::Constant(ref c) => c.fmt(f),
            Expression::Add(ref lhs, ref rhs) => 
                write!(f, "({} + {})", lhs, rhs),
            Expression::Sub(ref lhs, ref rhs) =>
                write!(f, "({} - {})", lhs, rhs),
            Expression::Mul(ref lhs, ref rhs) =>
                write!(f, "({} * {})", lhs, rhs),
            Expression::Divu(ref lhs, ref rhs) =>
                write!(f, "({} /u {})", lhs, rhs),
            Expression::Modu(ref lhs, ref rhs) =>
                write!(f, "({} %u {})", lhs, rhs),
            Expression::Divs(ref lhs, ref rhs) =>
                write!(f, "({} /s {})", lhs, rhs),
            Expression::Mods(ref lhs, ref rhs) =>
                write!(f, "({} %s {})", lhs, rhs),
            Expression::And(ref lhs, ref rhs) =>
                write!(f, "({} & {})", lhs, rhs),
            Expression::Or(ref lhs, ref rhs) =>
                write!(f, "({} | {})", lhs, rhs),
            Expression::Xor(ref lhs, ref rhs) =>
                write!(f, "({} ^ {})", lhs, rhs),
            Expression::Shl(ref lhs, ref rhs) =>
                write!(f, "({} << {})", lhs, rhs),
            Expression::Shr(ref lhs, ref rhs) =>
                write!(f, "({} >> {})", lhs, rhs),
            Expression::Cmpeq(ref lhs, ref rhs) =>
                write!(f, "({} == {})", lhs, rhs),
            Expression::Cmpneq(ref lhs, ref rhs) =>
                write!(f, "({} != {})", lhs, rhs),
            Expression::Cmplts(ref lhs, ref rhs) =>
                write!(f, "({} <s {})", lhs, rhs),
            Expression::Cmpltu(ref lhs, ref rhs) =>
                write!(f, "({} <u {})", lhs, rhs),
            Expression::Zext(ref bits, ref src) =>
                write!(f, "zext.{}({})", bits, src),
            Expression::Sext(ref bits, ref src) =>
                write!(f, "sext.{}({})", bits, src),
            Expression::Trun(ref bits, ref src) =>
                write!(f, "trun.{}({})", bits, src),
        }
    }
}
