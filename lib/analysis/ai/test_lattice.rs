//! This lattice is used for testing. It is only built when tests are run.

use analysis::ai::domain::*;
use analysis::ai;
use error::*;
use executor;
use il;
use memory;
use types::Endian;

pub type TestLatticeMemory<'m> = ai::memory::Memory<'m, TestLattice>;
pub type TestLatticeState<'m> = State<TestLatticeMemory<'m>, TestLattice>;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum TestLattice {
    Top(usize),
    Constant(il::Constant),
    Bottom(usize)
}


impl TestLattice {
    pub fn eval(expr: &Expression<TestLattice>) -> Result<TestLattice> {

        pub fn arith<F>(
            lhs: &TestLattice,
            rhs: &TestLattice,
            op: F
        ) -> Result<TestLattice> where F: Fn(&il::Constant, &il::Constant) -> Result<il::Constant> {
            Ok(match *lhs {
                TestLattice::Top(bits) => TestLattice::Top(bits),
                TestLattice::Constant(ref lhs_) => match *rhs {
                    TestLattice::Top(bits) => TestLattice::Top(bits),
                    TestLattice::Constant(ref rhs_) => TestLattice::Constant(op(lhs_, rhs_)?),
                    TestLattice::Bottom(_) => lhs.clone()
                },
                TestLattice::Bottom(_) => rhs.clone()
            })
        }

        match *expr {
            Expression::Value(ref constant) => Ok(constant.clone()),
            Expression::Add(ref lhs, ref rhs) =>
                arith(&TestLattice::eval(lhs)?, &TestLattice::eval(rhs)?, |l, r| {
                    let l = l.clone();
                    let r = r.clone();
                    let expr = il::Expression::add(l.into(), r.into())?;
                    executor::eval(&expr)
                }),
            _ => unimplemented!()
        }
    }


    pub fn constant(&self) -> Option<&il::Constant> {
        match *self {
            TestLattice::Constant(ref constant) => Some(constant),
            TestLattice::Top(_) |
            TestLattice::Bottom(_) => None
        }
    }
}


pub struct TestLatticeDomain {}


impl<'d> Domain<TestLatticeMemory<'d>, TestLattice> for TestLatticeDomain {
    fn eval(&self, expr: &Expression<TestLattice>) -> Result<TestLattice> {
        TestLattice::eval(expr)
    }

    fn store(&self,
             memory: &mut TestLatticeMemory,
             index: &TestLattice,
             value: TestLattice) -> Result<()> {

        if let Some(ref constant) = index.constant() {
            memory.store(constant.value(), value)
        }
        else {
            Ok(())
        }
    }

    fn load(&self,
            memory: &TestLatticeMemory,
            index: &TestLattice,
            bits: usize) -> Result<TestLattice> {

        if let Some(ref constant) = index.constant() {
            memory.load(constant.value(), bits)
        }
        else {
            Ok(TestLattice::Bottom(bits))
        }
    }

    fn brc(&self, _: &TestLattice, _: &TestLattice, state: TestLatticeState<'d>)
        -> Result<TestLatticeState<'d>> {

        Ok(state)
    }

    fn raise(&self, _: &TestLattice, state: TestLatticeState<'d>)
        -> Result<TestLatticeState<'d>> {

        Ok(state)
    }

    fn new_state(&self) -> TestLatticeState<'d> {
        State::new(TestLatticeMemory::new(Endian::Big))
    }
}


impl Value for TestLattice {
    fn join(&self, other: &TestLattice) -> Result<TestLattice> {
        Ok(match *self {
            TestLattice::Top(bits) => TestLattice::Top(bits),
            TestLattice::Constant(ref lhs) => match *other {
                TestLattice::Top(bits) => TestLattice::Top(bits),
                TestLattice::Constant(ref rhs) => {
                    if lhs == rhs {
                        TestLattice::Constant(lhs.clone())
                    }
                    else {
                        TestLattice::Top(lhs.bits())
                    }
                },
                TestLattice::Bottom(_) => TestLattice::Constant(lhs.clone())
            },
            TestLattice::Bottom(_) => other.clone()
        })
    }

    fn empty(bits: usize) -> TestLattice {
        TestLattice::Bottom(bits)
    }

    fn constant(constant: il::Constant) -> TestLattice {
        TestLattice::Constant(constant)
    }
}


impl memory::value::Value for TestLattice {
    fn constant(constant: il::Constant) -> TestLattice {
        TestLattice::Constant(constant)
    }

    fn bits(&self) -> usize {
        match *self {
            TestLattice::Top(bits) |
            TestLattice::Bottom(bits) => bits,
            TestLattice::Constant(ref constant) => constant.bits(),
        }
    }

    fn shl(&self, bits: usize) -> Result<TestLattice> {
        Ok(match *self {
            TestLattice::Top(_) |
            TestLattice::Bottom(_) => self.clone(),
            TestLattice::Constant(ref constant) => {
                let value = constant.value() << bits;
                let constant = il::const_(value, constant.bits());
                TestLattice::Constant(constant)
            }
        })
    }

    fn shr(&self, bits: usize) -> Result<TestLattice> {
        Ok(match *self {
            TestLattice::Top(_) |
            TestLattice::Bottom(_) => self.clone(),
            TestLattice::Constant(ref constant) => {
                let value = constant.value() >> bits;
                let constant = il::const_(value, constant.bits());
                TestLattice::Constant(constant)
            }
        })
    }

    fn trun(&self, bits: usize) -> Result<TestLattice> {
        Ok(match *self {
            TestLattice::Top(_) => TestLattice::Top(bits),
            TestLattice::Bottom(_) => TestLattice::Bottom(bits),
            TestLattice::Constant(ref constant) => {
                let constant = il::const_(constant.value(), bits);
                TestLattice::Constant(constant)
            }
        })
    }

    fn zext(&self, bits: usize) -> Result<TestLattice> {
        Ok(match *self {
            TestLattice::Top(_) => TestLattice::Top(bits),
            TestLattice::Bottom(_) => TestLattice::Bottom(bits),
            TestLattice::Constant(ref constant) => {
                let constant = il::const_(constant.value(), bits);
                TestLattice::Constant(constant)
            }
        })
    }

    fn or(&self, other: &TestLattice) -> Result<TestLattice> {
        Ok(match *self {
            TestLattice::Top(bits) => TestLattice::Top(bits),
            TestLattice::Bottom(bits) => match *other {
                TestLattice::Top(bits) => TestLattice::Top(bits),
                TestLattice::Constant(_) |
                TestLattice::Bottom(_) => TestLattice::Bottom(bits)
            },
            TestLattice::Constant(ref lhs) => {
                match *other {
                    TestLattice::Top(bits) => TestLattice::Top(bits),
                    TestLattice::Bottom(bits) => TestLattice::Bottom(bits),
                    TestLattice::Constant(ref rhs) => {
                        let constant = il::const_(lhs.value() | rhs.value(), lhs.bits());
                        TestLattice::Constant(constant)
                    }
                }
            }
        })
    }
}


impl Into<Expression<TestLattice>> for TestLattice {
    fn into(self) -> Expression<TestLattice> {
        Expression::Value(self)
    }
}