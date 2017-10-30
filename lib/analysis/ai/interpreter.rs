use analysis::fixed_point;
use analysis::ai::domain;
use error::*;
use il;


pub struct Interpreter<D: domain::Domain<M, V>, M: domain::Memory<V>, V: domain::Value> {
    pub m: ::std::marker::PhantomData<M>,
    pub v: ::std::marker::PhantomData<V>,
    pub domain: D
}


impl<D, M, V> Interpreter<D, M, V> where D: domain::Domain<M, V>,
                                         M: domain::Memory<V>,
                                         V: domain::Value {
    pub fn symbolize(&self, expression: &il::Expression, state: &domain::State<M, V>)
    -> domain::Expression<V> {

        match *expression {
            il::Expression::Scalar(ref scalar) => {
                match state.variable(scalar) {
                    Some(v) => {
                        domain::Expression::value(v.clone())
                    },
                    None => domain::Expression::value(V::empty(scalar.bits()))
                }
            },
            il::Expression::Constant(ref constant) =>
                domain::Expression::value(V::constant(constant.clone())),
            il::Expression::Add(ref lhs, ref rhs) =>
                domain::Expression::add(self.symbolize(lhs, state), self.symbolize(rhs, state)),
            il::Expression::Sub(ref lhs, ref rhs) =>
                domain::Expression::sub(self.symbolize(lhs, state), self.symbolize(rhs, state)),
            il::Expression::Mul(ref lhs, ref rhs) =>
                domain::Expression::mul(self.symbolize(lhs, state), self.symbolize(rhs, state)),
            il::Expression::Divu(ref lhs, ref rhs) =>
                domain::Expression::divu(self.symbolize(lhs, state), self.symbolize(rhs, state)),
            il::Expression::Modu(ref lhs, ref rhs) =>
                domain::Expression::modu(self.symbolize(lhs, state), self.symbolize(rhs, state)),
            il::Expression::Divs(ref lhs, ref rhs) =>
                domain::Expression::divs(self.symbolize(lhs, state), self.symbolize(rhs, state)),
            il::Expression::Mods(ref lhs, ref rhs) =>
                domain::Expression::mods(self.symbolize(lhs, state), self.symbolize(rhs, state)),
            il::Expression::And(ref lhs, ref rhs) =>
                domain::Expression::and(self.symbolize(lhs, state), self.symbolize(rhs, state)),
            il::Expression::Or(ref lhs, ref rhs) =>
                domain::Expression::or(self.symbolize(lhs, state), self.symbolize(rhs, state)),
            il::Expression::Xor(ref lhs, ref rhs) =>
                domain::Expression::xor(self.symbolize(lhs, state), self.symbolize(rhs, state)),
            il::Expression::Shl(ref lhs, ref rhs) =>
                domain::Expression::shl(self.symbolize(lhs, state), self.symbolize(rhs, state)),
            il::Expression::Shr(ref lhs, ref rhs) =>
                domain::Expression::shr(self.symbolize(lhs, state), self.symbolize(rhs, state)),
            il::Expression::Cmpeq(ref lhs, ref rhs) =>
                domain::Expression::cmpeq(self.symbolize(lhs, state), self.symbolize(rhs, state)),
            il::Expression::Cmpneq(ref lhs, ref rhs) =>
                domain::Expression::cmpneq(self.symbolize(lhs, state), self.symbolize(rhs, state)),
            il::Expression::Cmpltu(ref lhs, ref rhs) =>
                domain::Expression::cmpltu(self.symbolize(lhs, state), self.symbolize(rhs, state)),
            il::Expression::Cmplts(ref lhs, ref rhs) =>
                domain::Expression::cmplts(self.symbolize(lhs, state), self.symbolize(rhs, state)),
            il::Expression::Zext(bits, ref rhs) =>
                domain::Expression::zext(bits, self.symbolize(rhs, state)),
            il::Expression::Sext(bits, ref rhs) =>
                domain::Expression::sext(bits, self.symbolize(rhs, state)),
            il::Expression::Trun(bits, ref rhs) =>
                domain::Expression::trun(bits, self.symbolize(rhs, state))
        }
    }
}


impl<'a, D, M, V> fixed_point::FixedPointAnalysis<'a, domain::State<M, V>> for Interpreter<D, M, V>
    where D: 'a + domain::Domain<M, V>,
          M: 'a + domain::Memory<V>,
          V: 'a + domain::Value {
    fn trans(&self, location: il::RefProgramLocation<'a>, state: Option<domain::State<M, V>>)
    -> Result<domain::State<M, V>> {

        let mut state = match state {
            Some(state) => state,
            None => self.domain.new_state()
        };

        let state = match *location.function_location() {
            il::RefFunctionLocation::Instruction(_, ref instruction) => {
                match *instruction.operation() {
                    il::Operation::Assign { ref dst, ref src } => {
                        let expr = self.symbolize(src, &state);
                        state.set_variable(dst.clone(), self.domain.eval(&expr)?);
                        state
                    },
                    il::Operation::Store { ref index, ref src, .. } => {
                        let index = self.domain.eval(&self.symbolize(index, &state))?;
                        let src = self.domain.eval(&self.symbolize(src, &state))?;
                        state.memory.store(&index, src)?;
                        state
                    },
                    il::Operation::Load { ref dst, ref index, .. } => {
                        let index = self.domain.eval(&self.symbolize(index, &state))?;
                        let value = state.memory.load(&index, dst.bits())?;
                        state.set_variable(dst.clone(), value.clone());
                        state
                    },
                    il::Operation::Brc { ref target, ref condition } => {
                        let target = self.domain.eval(&self.symbolize(target, &state))?;
                        let condition = self.domain.eval(&self.symbolize(condition, &state))?;
                        self.domain.brc(&target, &condition, state)?
                    },
                    il::Operation::Raise { ref expr } => {
                        let expr = self.domain.eval(&self.symbolize(expr, &state))?;
                        self.domain.raise(&expr, state)?
                    }
                }
            },
            il::RefFunctionLocation::Edge(_) => {
                state
            },
            il::RefFunctionLocation::EmptyBlock(_) => {
                state
            }
        };

        Ok(state)
    }

    fn join(&self, state0: domain::State<M, V>, state1: &domain::State<M, V>)
    -> Result<domain::State<M, V>> {
        state0.join(state1)
    }
}