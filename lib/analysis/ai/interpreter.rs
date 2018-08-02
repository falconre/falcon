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

impl<D: domain::Domain<M, V>, M: domain::Memory<V>, V: domain::Value> Interpreter<D, M, V> {
    pub fn new(domain: D) -> Interpreter<D, M, V> {
        Interpreter {
            m: ::std::marker::PhantomData,
            v: ::std::marker::PhantomData,
            domain: domain
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
                        let expr = state.symbolize(src);
                        state.set_variable(dst.clone(), self.domain.eval(&expr)?);
                        state
                    },
                    il::Operation::Store { ref index, ref src } => {
                        let index = self.domain.eval(&state.symbolize(index))?;
                        let src = self.domain.eval(&state.symbolize(src))?;
                        self.domain.store(&mut state.memory, &index, src)?;
                        state
                    },
                    il::Operation::Load { ref dst, ref index } => {
                        let index = self.domain.eval(&state.symbolize(index))?;
                        let value = self.domain.load(&state.memory, &index, dst.bits())?;
                        state.set_variable(dst.clone(), value.clone());
                        state
                    },
                    il::Operation::Branch { ref target } => {
                        let target = self.domain.eval(&state.symbolize(target))?;
                        self.domain.brc(&target, state)?
                    },
                    il::Operation::Intrinsic { ref intrinsic } => {
                        intrinsic.scalars_written()
                            .into_iter()
                            .for_each(|scalar|
                                state.set_variable(
                                    scalar.clone(),
                                    V::top(scalar.bits())));
                        state
                    },
                    il::Operation::Nop => state
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


#[test]
fn test() {
    fn run() -> Result<()> {
        use analysis::ai::test_lattice::*;

        let mut cfg = il::ControlFlowGraph::new();

        let head_index = {
            cfg.new_block()?.index()
        };

        let left_index = {
            cfg.new_block()?.index()
        };

        let right_index = {
            cfg.new_block()?.index()
        };

        let tail_index = {
            let block = cfg.new_block()?;

            block.assign(il::scalar("$a0", 32), il::expr_const(0x570000, 32));
            block.assign(il::scalar("$a0", 32),
                il::Expression::add(il::expr_scalar("$a0", 32).into(),
                                    il::expr_const(0x7038, 32))?);

            block.index()
        };

        cfg.set_entry(head_index)?;

        cfg.unconditional_edge(head_index, left_index)?;
        cfg.unconditional_edge(head_index, right_index)?;
        cfg.unconditional_edge(left_index, tail_index)?;
        cfg.unconditional_edge(right_index, tail_index)?;

        let function = il::Function::new(0, cfg);

        let domain = TestLatticeDomain {};

        let interpreter = Interpreter::new(domain);

        let results = fixed_point::fixed_point_forward(interpreter, &function)?;

        let block = function.block(tail_index)
            .expect("Can't find block");
        let instruction = block.instruction(1)
            .expect("Can't find instruction");
        let rfl = il::RefFunctionLocation::Instruction(block, instruction);
        let rpl = il::RefProgramLocation::new(&function, rfl);

        let a0 = results[&rpl].variable(&il::scalar("$a0", 32))
            .expect("Can't find $a0");

        assert_eq!(*a0, TestLattice::Constant(il::const_(0x577038, 32)));

        Ok(())
    }

    run().unwrap();
}