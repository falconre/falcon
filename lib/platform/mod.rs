//! Platform models an external system like Linux or CGC.

use engine::*;
use error::*;
use il;

pub mod linux;
pub mod linux_x86;

pub use self::linux_x86::LinuxX86;


/// Platform provides generic interaction between Falcon and a modelled system.
pub trait Platform<P: Platform<P>> : Clone + Send + Sync {
    /// Handle an `Operation::Raise` from a `SymbolicEngine`. Returns a vec of tuples of produced
    /// `(Platform, SymbolicEngine)`.
    fn raise(self, expression: &il::Expression, engine: SymbolicEngine)
    -> Result<Vec<(P, SymbolicEngine)>>;

    /// Get each `Scalar` produced by this `Platform`.
    fn symbolic_scalars(&self) -> Vec<il::Scalar>;
}