//! A `Constant` holds a single value.

use il::*;
use num_bigint::{BigInt, BigUint, ToBigInt};
use num_traits::{FromPrimitive, ToPrimitive};
use std::fmt;
use std::ops::*;

/// A constant value for Falcon IL
///
/// IL Constants in Falcon are backed by both rust's `u64` primitive, and
/// `BigUint` from the `num-bigint` crate. This allows modelling and simulation
/// of instructions which must operate on values >64 bits in size. When a
/// Constant has 64 or less bits, the `u64` will be used, incurring minimal
/// performance overhead.
///
/// The Falcon IL Expression operations are provided as methods over `Constant`.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct Constant {
    value: BigUint,
    bits: usize
}


impl Constant {
    /// Create a new `Constant` with the given value and bitness.
    pub fn new(value: u64, bits: usize) -> Constant {
        Constant {
            value: Constant::trim_value(BigUint::from_u64(value).unwrap(),
                                        bits),
            bits: bits
        }
    }

    /// Create a new `Constant` from the given `BigUint`.
    pub fn new_big(value: BigUint, bits: usize) -> Constant {
        Constant {
            value: Constant::trim_value(value, bits),
            bits: bits
        }
    }

    /// Crates a constant from a decimal string of the value
    pub fn from_decimal_string(s: &String, bits: usize) -> Result<Constant> {
        let constant = Constant::new_big(s.parse()?, bits);
        Ok(if constant.bits() < bits {
            constant.zext(bits)?
        }
        else if constant.bits() > bits {
            constant.trun(bits)?
        }
        else {
            constant
        })
    }

    /// Create a new `Constant` with the given bits and a value of zero
    pub fn new_zero(bits: usize) -> Constant {
        Constant {
            value: BigUint::from_u64(0).unwrap(),
            bits: bits
        }
    }

    fn trim_value(value: BigUint, bits: usize) -> BigUint {
        let mask = BigUint::from_u64(1).unwrap() << bits;
        let mask = mask - BigUint::from_u64(1).unwrap();
        value & mask
    }

    /// Ugly trickery to convert BigUint to BigInt
    fn to_bigint(&self) -> BigInt {
        let sign_bit = self.value.clone() >> (self.bits - 1);
        if sign_bit == BigUint::from_u64(1).unwrap() {
            let mask = BigUint::from_i64(1).unwrap() << self.bits;
            let mask = mask - BigUint::from_i64(1).unwrap();
            let v = self.value.clone() ^ mask;
            let v = v + BigUint::from_u64(1).unwrap();
            let v = BigInt::from_i64(-1).unwrap() * v.to_bigint().unwrap();
            v
        }
        else {
            self.value.to_bigint().unwrap()
        }
    }

    /// Get the value of this `Constant` if it is a `u64`.
    pub fn value_u64(&self) -> Option<u64> {
        self.value.to_u64()
    }

    /// Get the value of this `Constant` if it is a `BigUint`.
    pub fn value(&self) -> &BigUint {
        &self.value
    }

    /// Get the number of bits for this `Constant`.
    pub fn bits(&self) -> usize {
        self.bits
    }

    /// Returns true if the value in this Constant is 0, false otherwise.
    pub fn is_zero(&self) -> bool {
        self.value_u64().map(|v| v == 0).unwrap_or(false)
    }

    /// Returns true if the value in this constant is 1, false otherwise.
    pub fn is_one(&self) -> bool {
        self.value_u64().map(|v| v == 1).unwrap_or(false)
    }

    pub fn add(&self, rhs: &Constant) -> Result<Constant> {
        if self.bits != rhs.bits() { Err(ErrorKind::Sort.into()) }
        else {
            Ok(Constant::new_big(
                self.value.clone() + rhs.value.clone(),
                self.bits))
        }
    }

    pub fn sub(&self, rhs: &Constant) -> Result<Constant> {
        if self.bits() != rhs.bits() { Err(ErrorKind::Sort.into()) }
        else {
            if self.value < rhs.value {
                let lhs = self.value.clone();
                let lhs = lhs | (BigUint::from_u64(1).unwrap() << self.bits);
                Ok(Constant::new_big(lhs - rhs.value.clone(), self.bits))
            }
            else {
                Ok(Constant::new_big(
                    self.value.clone().sub(rhs.value.clone()),
                    self.bits))
            }
        }
    }

    pub fn mul(&self, rhs: &Constant) -> Result<Constant> {
        if self.bits() != rhs.bits() { Err(ErrorKind::Sort.into()) }
        else {
            Ok(Constant::new_big(self.value.clone() * rhs.value.clone(),
                self.bits))
        }
    }

    pub fn divu(&self, rhs: &Constant) -> Result<Constant> {
        if self.bits() != rhs.bits() { Err(ErrorKind::Sort.into()) }
        else if rhs.is_zero() { Err(ErrorKind::DivideByZero.into()) }
        else {
            Ok(Constant::new_big(self.value.clone() / rhs.value.clone(),
                self.bits))
        }
    }

    pub fn modu(&self, rhs: &Constant) -> Result<Constant> {
        if self.bits() != rhs.bits() { Err(ErrorKind::Sort.into()) }
        else if rhs.is_zero() { Err(ErrorKind::DivideByZero.into()) }
        else {
            Ok(Constant::new_big(self.value.clone() % rhs.value.clone(),
                self.bits))
        }
    }

    pub fn divs(&self, rhs: &Constant) -> Result<Constant> {
        if self.bits() != rhs.bits() { Err(ErrorKind::Sort.into()) }
        else if rhs.is_zero() { Err(ErrorKind::DivideByZero.into()) }
        else {
            let lhs = self.to_bigint();
            let rhs = rhs.to_bigint();
            let r = lhs / rhs;
            if r >= BigInt::from_i64(0).unwrap() {
                Ok(Constant::new_big(r.to_biguint().unwrap(), self.bits))
            }
            else {
                let mask = BigInt::from_i64(1).unwrap() << self.bits;
                let mask = mask - BigInt::from_i64(1).unwrap();
                let r = (r - BigInt::from_u64(1).unwrap()) ^ mask;
                let r = r * BigInt::from_i64(-1).unwrap();
                Ok(Constant::new_big(r.to_biguint().unwrap(), self.bits))
            }
        }
    }

    pub fn mods(&self, rhs: &Constant) -> Result<Constant> {
        if self.bits() != rhs.bits() { Err(ErrorKind::Sort.into()) }
        else if rhs.is_zero() { Err(ErrorKind::DivideByZero.into()) }
        else {
            let lhs = self.to_bigint();
            let rhs = rhs.to_bigint();
            let r = lhs % rhs;
            if r >= BigInt::from_i64(0).unwrap() {
                Ok(Constant::new_big(r.to_biguint().unwrap(), self.bits))
            }
            else {
                let mask = BigInt::from_i64(1).unwrap() << self.bits;
                let mask = mask - BigInt::from_i64(1).unwrap();
                let r = (r - BigInt::from_u64(1).unwrap()) ^ mask;
                let r = r * BigInt::from_i64(-1).unwrap();
                Ok(Constant::new_big(r.to_biguint().unwrap(), self.bits))
            }
        }
    }

    pub fn and(&self, rhs: &Constant) -> Result<Constant> {
        if self.bits() != rhs.bits() { Err(ErrorKind::Sort.into()) }
        else {
            Ok(Constant::new_big(self.value.clone() & rhs.value.clone(),
                self.bits))
        }
    }

    pub fn or(&self, rhs: &Constant) -> Result<Constant> {
        if self.bits() != rhs.bits() { Err(ErrorKind::Sort.into()) }
        else {
            Ok(Constant::new_big(self.value.clone() | rhs.value.clone(), self.bits))
        }
    }

    pub fn xor(&self, rhs: &Constant) -> Result<Constant> {
        if self.bits() != rhs.bits() { Err(ErrorKind::Sort.into()) }
        else {
            Ok(Constant::new_big(self.value.clone() ^ rhs.value.clone(), self.bits))
        }
    }

    pub fn shl(&self, rhs: &Constant) -> Result<Constant> {
        if self.bits() != rhs.bits() { Err(ErrorKind::Sort.into()) }
        else {
            let r = rhs.value
                       .to_usize().map(|bits| self.value.clone() << bits)
                       .unwrap_or(BigUint::from_u64(0).unwrap());
            Ok(Constant::new_big(r, self.bits))
        }
    }

    pub fn shr(&self, rhs: &Constant) -> Result<Constant> {
        if self.bits() != rhs.bits() { Err(ErrorKind::Sort.into()) }
        else {
            let r = rhs.value
                       .to_usize().map(|bits| self.value.clone() >> bits)
                       .unwrap_or(BigUint::from_u64(0).unwrap());
            Ok(Constant::new_big(r, self.bits))
        }
    }

    pub fn cmpeq(&self, rhs: &Constant) -> Result<Constant> {
        if self.bits() != rhs.bits() { Err(ErrorKind::Sort.into()) }
        else if self.value == rhs.value {
            Ok(Constant::new(1, 1))
        }
        else {
            Ok(Constant::new(0, 1))
        }
    }

    pub fn cmpneq(&self, rhs: &Constant) -> Result<Constant> {
        if self.bits() != rhs.bits() { Err(ErrorKind::Sort.into()) }
        else if self.value == rhs.value {
            Ok(Constant::new(0, 1))
        }
        else {
            Ok(Constant::new(1, 1))
        }
    }

    pub fn cmpltu(&self, rhs: &Constant) -> Result<Constant> {
        if self.bits() != rhs.bits() { Err(ErrorKind::Sort.into()) }
        else if self.value < rhs.value {
            Ok(Constant::new(1, 1))
        }
        else {
            Ok(Constant::new(0, 1))
        }

    }

    pub fn cmplts(&self, rhs: &Constant) -> Result<Constant> {
        if self.bits() != rhs.bits() { return Err(ErrorKind::Sort.into()); }
        let lhs = self.to_bigint();
        let rhs = rhs.to_bigint();
        if lhs < rhs {
            Ok(Constant::new(1, 1))
        }
        else {
            Ok(Constant::new(0, 1))
        }
    }

    pub fn trun(&self, bits: usize) -> Result<Constant> {
        if bits >= self.bits() { Err(ErrorKind::Sort.into()) }
        else {
            Ok(Constant::new_big(self.value.clone(), bits))
        }
    }

    pub fn zext(&self, bits: usize) -> Result<Constant> {
        if bits <= self.bits() { Err(ErrorKind::Sort.into()) }
        else {
            Ok(Constant::new_big(self.value.clone(), bits))
        }
    }

    pub fn sext(&self, bits: usize) -> Result<Constant> {
        if bits <= self.bits() || bits % 8 > 0 { Err(ErrorKind::Sort.into()) }
        else {
            let sign_bit = self.value.clone() >> (self.bits - 1);
            let value = if sign_bit == BigUint::from_u64(1).unwrap() {
                let mask = BigUint::from_u64(1).unwrap() << bits;
                let mask = mask - BigUint::from_u64(1).unwrap();
                let mask = mask << self.bits;
                self.value.clone() | mask
            }
            else {
                self.value.clone()
            };
            Ok(Constant::new_big(value, bits))
        }
    }
}


impl fmt::Display for Constant {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "0x:{:X}:{}", self.value, self.bits)
    }
}


impl Into<Expression> for Constant {
    fn into(self) -> Expression {
        Expression::constant(self)
    }
}


#[test]
fn constant_add() {
    assert_eq!(Constant::new(1, 64).add(&Constant::new(1, 64)).unwrap(),
               Constant::new(2, 64));
    assert_eq!(Constant::new(0xff, 8).add(&Constant::new(1, 8)).unwrap(),
               Constant::new(0, 8));
}

#[test]
fn constant_sub() {
    assert_eq!(Constant::new(1, 64).sub(&Constant::new(1, 64)).unwrap(),
               Constant::new(0, 64));
    assert_eq!(Constant::new(0, 64).sub(&Constant::new(1, 64)).unwrap(),
               Constant::new(0xffffffffffffffff, 64));
}

#[test]
fn constant_mul() {
    assert_eq!(Constant::new(6, 64).mul(&Constant::new(4, 64)).unwrap(),
               Constant::new(24, 64));
}

#[test]
fn constant_divu() {
    assert_eq!(Constant::new(6, 64).divu(&Constant::new(4, 64)).unwrap(),
               Constant::new(1, 64));
}

#[test]
fn constant_modu() {
    assert_eq!(Constant::new(6, 64).modu(&Constant::new(4, 64)).unwrap(),
               Constant::new(2, 64));
}

#[test]
fn constant_divs() {
    assert_eq!(Constant::new(6, 64).divs(&Constant::new(4, 64)).unwrap(),
               Constant::new(1, 64));
}

#[test]
fn constant_mods() {
    assert_eq!(Constant::new(6, 64).mods(&Constant::new(4, 64)).unwrap(),
               Constant::new(2, 64));
}

#[test]
fn constant_and() {
    assert_eq!(Constant::new(0xff00ff, 64).and(&Constant::new(0xf0f0f0, 64)).unwrap(),
               Constant::new(0xf000f0, 64));
}

#[test]
fn constant_or() {
    assert_eq!(Constant::new(0xff00ff, 64).or(&Constant::new(0xf0f0f0, 64)).unwrap(),
               Constant::new(0xfff0ff, 64));
}

#[test]
fn constant_xor() {
    assert_eq!(Constant::new(0xff00ff, 64).xor(&Constant::new(0xf0f0f0, 64)).unwrap(),
               Constant::new(0x0ff00f, 64));
}

#[test]
fn constant_shl() {
    assert_eq!(Constant::new(1, 64).shl(&Constant::new(8, 64)).unwrap(),
               Constant::new(0x100, 64));
}

#[test]
fn constant_shr() {
    assert_eq!(Constant::new(0x100, 64).shr(&Constant::new(8, 64)).unwrap(),
               Constant::new(1, 64));
}

#[test]
fn constant_cmpeq() {
    assert_eq!(Constant::new(1, 64).cmpeq(&Constant::new(1, 64)).unwrap(),
               Constant::new(1, 1));
    assert_eq!(Constant::new(1, 64).cmpeq(&Constant::new(2, 64)).unwrap(),
               Constant::new(0, 1));
}

#[test]
fn constant_cmpneq() {
    assert_eq!(Constant::new(1, 64).cmpneq(&Constant::new(1, 64)).unwrap(),
               Constant::new(0, 1));
    assert_eq!(Constant::new(1, 64).cmpneq(&Constant::new(2, 64)).unwrap(),
               Constant::new(1, 1));
}

#[test]
fn constant_cmpltu() {
    assert_eq!(Constant::new(1, 64).cmpltu(&Constant::new(1, 64)).unwrap(),
               Constant::new(0, 1));
    assert_eq!(Constant::new(1, 64).cmpltu(&Constant::new(2, 64)).unwrap(),
               Constant::new(1, 1));
}

#[test]
fn constant_cmplts() {
    assert_eq!(Constant::new(1, 64).cmplts(&Constant::new(1, 64)).unwrap(),
               Constant::new(0, 1));
    assert_eq!(Constant::new(1, 64).cmplts(&Constant::new(2, 64)).unwrap(),
               Constant::new(1, 1));
    assert_eq!(Constant::new(0xffffffffffffffff, 64).cmplts(&Constant::new(1, 64)).unwrap(),
               Constant::new(1, 1));
}