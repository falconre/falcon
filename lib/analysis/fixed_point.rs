//! A fixed-point engine for data-flow analysis.

use error::*;
use il;
use std::collections::{HashMap, HashSet};
use std::fmt::Debug;


/// A trait which implements a forward, flow-sensitive analysis to a
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
    fn join(&self, state0: State, state1: &State) -> Result<State>;
}


/// A forward, work-list data-flow analysis algorithm.
pub fn fixed_point_forward<'f, Analysis, State> (
    analysis: Analysis,
    function: &'f il::Function
) -> Result<HashMap<il::RefProgramLocation<'f>, State>>
where Analysis: FixedPointAnalysis<'f, State>, State: 'f + Clone + Debug + Eq + PartialEq {
    let mut states: HashMap<il::RefProgramLocation<'f>, State> = HashMap::new();

    let mut queue: HashSet<il::RefProgramLocation<'f>> = HashSet::new();

    // Find the entry block to the function.
    let entry_index = function.control_flow_graph()
                              .entry()
                              .ok_or("Function's control flow graph must have entry")?;
    let entry_block = function.control_flow_graph()
                              .block(entry_index)
                              .ok_or(format!("Could not find block for {}", entry_index))?;

    // Add our first initial state.
    match entry_block.instructions().first() {
        Some(ref instruction) => {
            let location = il::RefFunctionLocation::Instruction(entry_block, instruction);
            let location = il::RefProgramLocation::new(function, location);
            queue.insert(location.clone());
        },
        None => {
            let location = il::RefFunctionLocation::EmptyBlock(entry_block);
            let location = il::RefProgramLocation::new(function, location);
            queue.insert(location.clone());
        }
    }

    while !queue.is_empty() {
        let location = queue.iter().next().unwrap().clone();
        queue.remove(&location);

        let location_predecessors = location.backward()?;

        let state = location_predecessors.iter().fold(None, |s, p| {
            match states.get(p) {
                Some(in_state) => match s {
                    Some(s) => Some(analysis.join(s, in_state).unwrap()),
                    None => Some(in_state.clone())
                },
                None => s
            }
        });

        let state = analysis.trans(location.clone(), state)?;

        if let Some(in_state) = states.get(&location) {
            if state == *in_state {
                continue;
            }
        }

        states.insert(location.clone(), state);

        for successor in location.forward()? {
            queue.insert(successor);
        }
    }

    Ok(states)
}