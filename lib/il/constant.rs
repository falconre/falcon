//! A `Constant` holds a single value.

use crate::Error;
use num_bigint::{BigInt, BigUint, ToBigInt};
use num_traits::{FromPrimitive, One, ToPrimitive, Zero};
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
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
    bits: usize,
}

impl Constant {
    /// Create a new `Constant` with the given value and bitness.
    pub fn new(value: u64, bits: usize) -> Constant {
        Constant {
            value: Constant::trim_value(BigUint::from_u64(value).unwrap(), bits),
            bits,
        }
    }

    /// Create a new `Constant` from the given `BigUint`.
    pub fn new_big(value: BigUint, bits: usize) -> Constant {
        Constant {
            value: Constant::trim_value(value, bits),
            bits,
        }
    }

    /// Crates a constant from a decimal string of the value
    pub fn from_decimal_string(s: &str, bits: usize) -> Result<Constant, Error> {
        let constant = Constant::new_big(s.parse()?, bits);
        Ok(match constant.bits().cmp(&bits) {
            Ordering::Less => constant.zext(bits)?,
            Ordering::Greater => constant.trun(bits)?,
            Ordering::Equal => constant,
        })
    }

    /// Create a new `Constant` with the given bits and a value of zero
    pub fn new_zero(bits: usize) -> Constant {
        Constant {
            value: BigUint::from_u64(0).unwrap(),
            bits,
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
            BigInt::from_i64(-1).unwrap() * v.to_bigint().unwrap()
        } else {
            self.value.to_bigint().unwrap()
        }
    }

    /// Get the value of this `Constant` if it is a `u64`.
    pub fn value_u64(&self) -> Option<u64> {
        self.value.to_u64()
    }

    /// Sign-extend the constant out to 64-bits, and return it as an `i64`
    pub fn value_i64(&self) -> Option<i64> {
        match self.bits().cmp(&64) {
            Ordering::Greater => None,
            Ordering::Equal => self.value.to_u64().map(|v| v as i64),
            Ordering::Less => self.sext(64).ok()?.value.to_u64().map(|v| v as i64),
        }
    }

    /// Get the value of this `Constant` if it is a `u128`.
    pub fn value_u128(&self) -> Option<u128> {
        self.value.to_u128()
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
        self.value.is_zero()
    }

    /// Returns true if the value in this constant is 1, false otherwise.
    pub fn is_one(&self) -> bool {
        self.value.is_one()
    }

    pub fn add(&self, rhs: &Constant) -> Result<Constant, Error> {
        if self.bits != rhs.bits() {
            Err(Error::Sort)
        } else {
            Ok(Constant::new_big(
                self.value.clone() + rhs.value.clone(),
                self.bits,
            ))
        }
    }

    pub fn sub(&self, rhs: &Constant) -> Result<Constant, Error> {
        if self.bits() != rhs.bits() {
            Err(Error::Sort)
        } else if self.value < rhs.value {
            let lhs = self.value.clone();
            let lhs = lhs | (BigUint::from_u64(1).unwrap() << self.bits);
            Ok(Constant::new_big(lhs - rhs.value.clone(), self.bits))
        } else {
            Ok(Constant::new_big(
                self.value.clone().sub(rhs.value.clone()),
                self.bits,
            ))
        }
    }

    pub fn mul(&self, rhs: &Constant) -> Result<Constant, Error> {
        if self.bits() != rhs.bits() {
            Err(Error::Sort)
        } else {
            Ok(Constant::new_big(
                self.value.clone() * rhs.value.clone(),
                self.bits,
            ))
        }
    }

    pub fn divu(&self, rhs: &Constant) -> Result<Constant, Error> {
        if self.bits() != rhs.bits() {
            Err(Error::Sort)
        } else if rhs.is_zero() {
            Err(Error::DivideByZero)
        } else {
            Ok(Constant::new_big(
                self.value.clone() / rhs.value.clone(),
                self.bits,
            ))
        }
    }

    pub fn modu(&self, rhs: &Constant) -> Result<Constant, Error> {
        if self.bits() != rhs.bits() {
            Err(Error::Sort)
        } else if rhs.is_zero() {
            Err(Error::DivideByZero)
        } else {
            Ok(Constant::new_big(
                self.value.clone() % rhs.value.clone(),
                self.bits,
            ))
        }
    }

    pub fn divs(&self, rhs: &Constant) -> Result<Constant, Error> {
        if self.bits() != rhs.bits() {
            Err(Error::Sort)
        } else if rhs.is_zero() {
            Err(Error::DivideByZero)
        } else {
            let lhs = self.to_bigint();
            let rhs = rhs.to_bigint();
            let r = lhs / rhs;
            if r >= BigInt::from_i64(0).unwrap() {
                Ok(Constant::new_big(r.to_biguint().unwrap(), self.bits))
            } else {
                let mask = BigInt::from_i64(1).unwrap() << self.bits;
                let mask = mask - BigInt::from_i64(1).unwrap();
                let r = (r - BigInt::from_u64(1).unwrap()) ^ mask;
                let r = r * BigInt::from_i64(-1).unwrap();
                Ok(Constant::new_big(r.to_biguint().unwrap(), self.bits))
            }
        }
    }

    pub fn mods(&self, rhs: &Constant) -> Result<Constant, Error> {
        if self.bits() != rhs.bits() {
            Err(Error::Sort)
        } else if rhs.is_zero() {
            Err(Error::DivideByZero)
        } else {
            let lhs = self.to_bigint();
            let rhs = rhs.to_bigint();
            let r = lhs % rhs;
            if r >= BigInt::from_i64(0).unwrap() {
                Ok(Constant::new_big(r.to_biguint().unwrap(), self.bits))
            } else {
                let mask = BigInt::from_i64(1).unwrap() << self.bits;
                let mask = mask - BigInt::from_i64(1).unwrap();
                let r = (r - BigInt::from_u64(1).unwrap()) ^ mask;
                let r = r * BigInt::from_i64(-1).unwrap();
                Ok(Constant::new_big(r.to_biguint().unwrap(), self.bits))
            }
        }
    }

    pub fn and(&self, rhs: &Constant) -> Result<Constant, Error> {
        if self.bits() != rhs.bits() {
            Err(Error::Sort)
        } else {
            Ok(Constant::new_big(
                self.value.clone() & rhs.value.clone(),
                self.bits,
            ))
        }
    }

    pub fn or(&self, rhs: &Constant) -> Result<Constant, Error> {
        if self.bits() != rhs.bits() {
            Err(Error::Sort)
        } else {
            Ok(Constant::new_big(
                self.value.clone() | rhs.value.clone(),
                self.bits,
            ))
        }
    }

    pub fn xor(&self, rhs: &Constant) -> Result<Constant, Error> {
        if self.bits() != rhs.bits() {
            Err(Error::Sort)
        } else {
            Ok(Constant::new_big(
                self.value.clone() ^ rhs.value.clone(),
                self.bits,
            ))
        }
    }

    pub fn shl(&self, rhs: &Constant) -> Result<Constant, Error> {
        if self.bits() != rhs.bits() {
            Err(Error::Sort)
        } else {
            // If, for some reason, an analysis generates a very large shift
            // value (for example << 0xFFFFFFFF_FFFFFFFF:64), this will cause
            // the bigint library to attempt gigantic memory allocations, and
            // crash. We have a basic sanity check here to just set the value
            // to 0 if we are shifting left by a value greater than the variable
            // width, which is the correct behavior.
            let r = rhs
                .value
                .to_usize()
                .map(|bits| {
                    if bits >= self.bits() {
                        BigUint::from_u64(0).unwrap()
                    } else {
                        self.value.clone() << bits
                    }
                })
                .unwrap_or_else(|| BigUint::from_u64(0).unwrap());
            Ok(Constant::new_big(r, self.bits))
        }
    }

    pub fn shr(&self, rhs: &Constant) -> Result<Constant, Error> {
        if self.bits() != rhs.bits() {
            Err(Error::Sort)
        } else {
            let r = rhs
                .value
                .to_usize()
                .map(|bits| self.value.clone() >> bits)
                .unwrap_or_else(|| BigUint::from_u64(0).unwrap());
            Ok(Constant::new_big(r, self.bits))
        }
    }

    pub fn ashr(&self, rhs: &Constant) -> Result<Constant, Error> {
        if self.bits() != rhs.bits() {
            Err(Error::Sort)
        } else {
            let r = rhs
                .value
                .to_usize()
                .map(|bits| {
                    let value = self.value() >> bits;
                    let msb = self.value() >> (self.bits - 1);
                    if msb.is_zero() {
                        value
                    } else {
                        let all_one = BigUint::from_u64(u64::MAX).unwrap();
                        let fill = all_one << (self.bits - bits);
                        fill | value
                    }
                })
                .unwrap_or_else(|| BigUint::from_u64(0).unwrap());
            Ok(Constant::new_big(r, self.bits))
        }
    }

    pub fn cmpeq(&self, rhs: &Constant) -> Result<Constant, Error> {
        if self.bits() != rhs.bits() {
            Err(Error::Sort)
        } else if self.value == rhs.value {
            Ok(Constant::new(1, 1))
        } else {
            Ok(Constant::new(0, 1))
        }
    }

    pub fn cmpneq(&self, rhs: &Constant) -> Result<Constant, Error> {
        if self.bits() != rhs.bits() {
            Err(Error::Sort)
        } else if self.value == rhs.value {
            Ok(Constant::new(0, 1))
        } else {
            Ok(Constant::new(1, 1))
        }
    }

    pub fn cmpltu(&self, rhs: &Constant) -> Result<Constant, Error> {
        if self.bits() != rhs.bits() {
            Err(Error::Sort)
        } else if self.value < rhs.value {
            Ok(Constant::new(1, 1))
        } else {
            Ok(Constant::new(0, 1))
        }
    }

    pub fn cmplts(&self, rhs: &Constant) -> Result<Constant, Error> {
        if self.bits() != rhs.bits() {
            return Err(Error::Sort);
        }
        let lhs = self.to_bigint();
        let rhs = rhs.to_bigint();
        if lhs < rhs {
            Ok(Constant::new(1, 1))
        } else {
            Ok(Constant::new(0, 1))
        }
    }

    pub fn trun(&self, bits: usize) -> Result<Constant, Error> {
        if bits >= self.bits() {
            Err(Error::Sort)
        } else {
            Ok(Constant::new_big(self.value.clone(), bits))
        }
    }

    pub fn zext(&self, bits: usize) -> Result<Constant, Error> {
        if bits <= self.bits() {
            Err(Error::Sort)
        } else {
            Ok(Constant::new_big(self.value.clone(), bits))
        }
    }

    pub fn sext(&self, bits: usize) -> Result<Constant, Error> {
        if bits <= self.bits() || bits % 8 > 0 {
            Err(Error::Sort)
        } else {
            let sign_bit = self.value.clone() >> (self.bits - 1);
            let value = if sign_bit == BigUint::from_u64(1).unwrap() {
                let mask = BigUint::from_u64(1).unwrap() << bits;
                let mask = mask - BigUint::from_u64(1).unwrap();
                let mask = mask << self.bits;
                self.value.clone() | mask
            } else {
                self.value.clone()
            };
            Ok(Constant::new_big(value, bits))
        }
    }
}

impl fmt::Display for Constant {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "0x{:X}:{}", self.value, self.bits)
    }
}

#[test]
fn constant_add() {
    assert_eq!(
        Constant::new(1, 64).add(&Constant::new(1, 64)).unwrap(),
        Constant::new(2, 64)
    );
    assert_eq!(
        Constant::new(0xff, 8).add(&Constant::new(1, 8)).unwrap(),
        Constant::new(0, 8)
    );
}

#[test]
fn constant_sub() {
    assert_eq!(
        Constant::new(1, 64).sub(&Constant::new(1, 64)).unwrap(),
        Constant::new(0, 64)
    );
    assert_eq!(
        Constant::new(0, 64).sub(&Constant::new(1, 64)).unwrap(),
        Constant::new(0xffffffffffffffff, 64)
    );
}

#[test]
fn constant_mul() {
    assert_eq!(
        Constant::new(6, 64).mul(&Constant::new(4, 64)).unwrap(),
        Constant::new(24, 64)
    );
}

#[test]
fn constant_divu() {
    assert_eq!(
        Constant::new(6, 64).divu(&Constant::new(4, 64)).unwrap(),
        Constant::new(1, 64)
    );
}

#[test]
fn constant_modu() {
    assert_eq!(
        Constant::new(6, 64).modu(&Constant::new(4, 64)).unwrap(),
        Constant::new(2, 64)
    );
}

#[test]
fn constant_divs() {
    assert_eq!(
        Constant::new(6, 64).divs(&Constant::new(4, 64)).unwrap(),
        Constant::new(1, 64)
    );
}

#[test]
fn constant_mods() {
    assert_eq!(
        Constant::new(6, 64).mods(&Constant::new(4, 64)).unwrap(),
        Constant::new(2, 64)
    );
}

#[test]
fn constant_and() {
    assert_eq!(
        Constant::new(0xff00ff, 64)
            .and(&Constant::new(0xf0f0f0, 64))
            .unwrap(),
        Constant::new(0xf000f0, 64)
    );
}

#[test]
fn constant_or() {
    assert_eq!(
        Constant::new(0xff00ff, 64)
            .or(&Constant::new(0xf0f0f0, 64))
            .unwrap(),
        Constant::new(0xfff0ff, 64)
    );
}

#[test]
fn constant_xor() {
    assert_eq!(
        Constant::new(0xff00ff, 64)
            .xor(&Constant::new(0xf0f0f0, 64))
            .unwrap(),
        Constant::new(0x0ff00f, 64)
    );
}

#[test]
fn constant_shl() {
    assert_eq!(
        Constant::new(1, 64).shl(&Constant::new(8, 64)).unwrap(),
        Constant::new(0x100, 64)
    );
}

#[test]
fn constant_shr() {
    assert_eq!(
        Constant::new(0x100, 64).shr(&Constant::new(8, 64)).unwrap(),
        Constant::new(1, 64)
    );
}

#[test]
fn constant_ashr() {
    assert_eq!(
        Constant::new(0x40000000, 32)
            .ashr(&Constant::new(0x10, 32))
            .unwrap(),
        Constant::new(0x00004000, 32)
    );
    assert_eq!(
        Constant::new(0x80000000, 32)
            .ashr(&Constant::new(0x10, 32))
            .unwrap(),
        Constant::new(0xffff8000, 32)
    );
}

#[test]
fn constant_cmpeq() {
    assert_eq!(
        Constant::new(1, 64).cmpeq(&Constant::new(1, 64)).unwrap(),
        Constant::new(1, 1)
    );
    assert_eq!(
        Constant::new(1, 64).cmpeq(&Constant::new(2, 64)).unwrap(),
        Constant::new(0, 1)
    );
}

#[test]
fn constant_cmpneq() {
    assert_eq!(
        Constant::new(1, 64).cmpneq(&Constant::new(1, 64)).unwrap(),
        Constant::new(0, 1)
    );
    assert_eq!(
        Constant::new(1, 64).cmpneq(&Constant::new(2, 64)).unwrap(),
        Constant::new(1, 1)
    );
}

#[test]
fn constant_cmpltu() {
    assert_eq!(
        Constant::new(1, 64).cmpltu(&Constant::new(1, 64)).unwrap(),
        Constant::new(0, 1)
    );
    assert_eq!(
        Constant::new(1, 64).cmpltu(&Constant::new(2, 64)).unwrap(),
        Constant::new(1, 1)
    );
}

#[test]
fn constant_cmplts() {
    assert_eq!(
        Constant::new(1, 64).cmplts(&Constant::new(1, 64)).unwrap(),
        Constant::new(0, 1)
    );
    assert_eq!(
        Constant::new(1, 64).cmplts(&Constant::new(2, 64)).unwrap(),
        Constant::new(1, 1)
    );
    assert_eq!(
        Constant::new(0xffffffffffffffff, 64)
            .cmplts(&Constant::new(1, 64))
            .unwrap(),
        Constant::new(1, 1)
    );
}
