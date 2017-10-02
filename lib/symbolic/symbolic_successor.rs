use symbolic::*;
use il;

/// The type of successor from execution of an `Operation` over a `SymbolicEngine`.
#[derive(Clone)]
pub enum SuccessorType {
    /// Control flow should contine normally, with no special considerations.
    FallThrough,
    /// Control flow should branch to the given address.
    Branch(u64),
    /// A `Platform` must handle a `Raise` instruction, and then control flow
    /// should continue normally.
    Raise(il::Expression)
}


/// A `SymbolicSuccessor` is the result of executing an `Operation` over a
/// `SymbolicEngine`.
#[derive(Clone)]
pub struct SymbolicSuccessor {
    type_: SuccessorType,
    engine: SymbolicEngine
}


impl SymbolicSuccessor {
    pub(crate) fn new(engine: SymbolicEngine, type_: SuccessorType)
        -> SymbolicSuccessor {

        SymbolicSuccessor {
            engine: engine,
            type_: type_
        }
    }

    /// Get the type of this `SymbolicSuccessor`.
    pub fn type_(&self) -> &SuccessorType {
        &self.type_
    }

    /// Consume this `SymbolicSuccessor` and turn it into a `SymbolicEngine`.
    pub fn into_engine(self) -> SymbolicEngine {
        self.engine
    }
}


impl Into<SymbolicEngine> for SymbolicSuccessor {
    fn into(self) -> SymbolicEngine {
        self.engine
    }
}