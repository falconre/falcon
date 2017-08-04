use engine::engine::*;
use error::*;
use il;

pub mod linux;
pub mod linux_x86;

pub trait Platform<P: Platform<P>> : Clone {
    fn raise(self, expression: &il::Expression, engine: SymbolicEngine)
    -> Result<Vec<(P, SymbolicEngine)>>;

    fn symbolic_variables(&self) -> Vec<il::Scalar>;
}