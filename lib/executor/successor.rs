//! A successor after concrete evaluation of a Falcon IL Instruction.

use executor::State;
use il;


/// A representation of the successor location in an `il::Program` after
/// execution of an `il::Operation`.
#[derive(Clone, Debug)]
pub enum SuccessorType {
    FallThrough,
    Branch(u64),
    Raise(il::Expression)
}


/// The result of executing an `il::Operation` over a `State`.
#[derive(Clone)]
pub struct Successor<'s> {
    state: State<'s>,
    type_: SuccessorType
}


impl<'s> Successor<'s> {
    pub(crate) fn new(state: State<'s>, type_: SuccessorType) -> Successor<'s> {
        Successor {
            state: state,
            type_: type_
        }
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


/// Turn this `Successor` into its `State`, discarding the `SuccessorType`.
impl<'e> Into<State<'e>> for Successor<'e> {
    fn into(self) -> State<'e> {
        self.state
    }
}