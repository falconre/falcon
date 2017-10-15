use error::*;
use il;
use std::collections::{BTreeMap, VecDeque};
use std::fmt::Debug;


/// A trait which implements a forwards, flow-sensitive analysis to a
/// fixed point.
pub trait FixedPointAnalysis<'f, State: 'f + Clone + Debug + Eq + PartialEq> {
    /// Given an input state for a block, create an output state for this
    /// block.
    fn trans(
        &self,
        location: il::RefProgramLocation<'f>,
        state: Option<State>
    ) -> Result<State>;

    /// Given two states, join them into one state.
    fn join(&self, state0: State, state1: &'f State) -> Result<State>;
}


/// A forward, work-list data-flow analysis algorithm.
pub fn fixed_point_forward<'f, Analysis, State> (
    analysis: Analysis,
    function: &'f il::Function
) -> Result<BTreeMap<il::RefProgramLocation<'f>, State>>
where Analysis: FixedPointAnalysis<'f, State>, State: 'f + Clone + Debug + Eq + PartialEq {
    let mut states: BTreeMap<il::RefProgramLocation<'f>, State> = BTreeMap::new();

    let mut queue: VecDeque<il::RefProgramLocation> = VecDeque::new();

    // Populate all initial states, and fill the queue
    for block in function.blocks() {
        if block.is_empty() {
            let location = il::RefFunctionLocation::EmptyBlock(block);
            let location = il::RefProgramLocation::new(function, location);
            let state = analysis.trans(location.clone(), None)?;
            queue.push_back(location.clone());
            states.insert(location, state);
        }
        else {
            for instruction in block.instructions() {
                let location = il::RefFunctionLocation::Instruction(block, instruction);
            let location = il::RefProgramLocation::new(function, location);
                let state = analysis.trans(location.clone(), None)?;
                queue.push_back(location.clone());
                states.insert(location, state);
            }
        }
    }

    while !queue.is_empty() {
        let location = queue.pop_front().unwrap();

        let state = match states.get(&location) {
            Some(state) => analysis.trans(location.clone(), Some(state.clone()))?,
            None => analysis.trans(location.clone(), None)?
        };

        if let Some(in_state) = states.get(&location) {
            if state == *in_state {
                continue;
            }
        }

        for successor in location.advance_forward()? {
            queue.push_back(successor);
        }
    }

    Ok(states)
}