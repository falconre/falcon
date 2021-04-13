//! A successor after concrete evaluation of a Falcon IL Instruction.

use crate::executor::State;
use crate::il;

/// A representation of the successor location in an `il::Program` after
/// execution of an `il::Operation`.
#[derive(Clone, Debug)]
pub enum SuccessorType {
    FallThrough,
    Branch(u64),
    Intrinsic(il::Intrinsic),
}

/// The result of executing an `il::Operation` over a `State`.
#[derive(Clone)]
pub struct Successor {
    pub(crate) state: State,
    type_: SuccessorType,
}

impl Successor {
    pub(crate) fn new(state: State, type_: SuccessorType) -> Successor {
        Successor { state, type_ }
    }

    /// Get the `SuccessorType` of this `Successor`.
    pub fn type_(&self) -> &SuccessorType {
        &self.type_
    }

    /// Get the `State` of this `Successor`.
    pub fn state(&self) -> &State {
        &self.state
    }
}
