//! An interpreter over abstract domains.

use analysis::fixed_point;
use analysis::ai::domain;
use error::*;
use il;


/// An interpreter for abstract domains.
pub struct Interpreter<D: domain::Domain<M, V>, M: domain::Memory<V>, V: domain::Value> {
    pub m: ::std::marker::PhantomData<M>,
    pub v: ::std::marker::PhantomData<V>,
    pub domain: D
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
                        let expr = state.symbolize(src);
                        state.set_variable(dst.clone(), self.domain.eval(&expr)?);
                        state
                    },
                    il::Operation::Store { ref index, ref src, .. } => {
                        let index = self.domain.eval(&state.symbolize(index))?;
                        let src = self.domain.eval(&state.symbolize(src))?;
                        self.domain.store(&mut state.memory, &index, src)?;
                        state
                    },
                    il::Operation::Load { ref dst, ref index, .. } => {
                        let index = self.domain.eval(&state.symbolize(index))?;
                        let value = self.domain.load(&state.memory, &index, dst.bits())?;
                        state.set_variable(dst.clone(), value.clone());
                        state
                    },
                    il::Operation::Brc { ref target, ref condition } => {
                        let target = self.domain.eval(&state.symbolize(target))?;
                        let condition = self.domain.eval(&state.symbolize(condition))?;
                        self.domain.brc(&target, &condition, state)?
                    },
                    il::Operation::Raise { ref expr } => {
                        let expr = self.domain.eval(&state.symbolize(expr))?;
                        self.domain.raise(&expr, state)?
                    }
                }
            },
            il::RefFunctionLocation::Edge(_) |
            il::RefFunctionLocation::EmptyBlock(_) => state
        };

        Ok(state)
    }

    fn join(&self, state0: domain::State<M, V>, state1: &domain::State<M, V>)
        -> Result<domain::State<M, V>> {
            
        state0.join(state1)
    }
}