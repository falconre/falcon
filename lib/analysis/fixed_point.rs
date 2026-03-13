//! A fixed-point engine for data-flow analysis.

use crate::{il, Error};
use std::collections::{HashMap, VecDeque};
use std::fmt::Debug;

const DEFAULT_MAX_ANALYSIS_STEPS: usize = 250000;

/// A trait which implements a forward, flow-sensitive analysis to a
/// fixed point.
pub trait FixedPointAnalysis<'f, State: 'f + Clone + Debug + PartialOrd> {
    /// Given an input state for a block, create an output state for this
    /// block.
    fn trans(
        &self,
        location: il::RefProgramLocation<'f>,
        state: Option<State>,
    ) -> Result<State, Error>;

    /// Given two states, join them into one state.
    fn join(&self, state0: State, state1: &State) -> Result<State, Error>;
}

/// A forward, work-list data-flow analysis algorithm.
///
/// When force is true, the partial order over inputs is forced by joining
/// states which do not inherently enforce the partial order.
pub fn fixed_point_forward_options<'f, Analysis, State>(
    analysis: Analysis,
    function: &'f il::Function,
    force: bool,
    max_analysis_steps: usize,
) -> Result<HashMap<il::ProgramLocation, State>, Error>
where
    Analysis: FixedPointAnalysis<'f, State>,
    State: 'f + Clone + Debug + PartialOrd,
{
    let mut states: HashMap<il::ProgramLocation, State> = HashMap::new();

    let mut queue: VecDeque<il::ProgramLocation> = VecDeque::new();

    // Find the entry block to the function.
    let entry_index = function
        .control_flow_graph()
        .entry()
        .ok_or(Error::FixedPointRequiresEntry)?;
    let entry_block = function.control_flow_graph().block(entry_index)?;

    match entry_block.instructions().first() {
        Some(instruction) => {
            let location = il::RefFunctionLocation::Instruction(entry_block, instruction);
            let location = il::RefProgramLocation::new(function, location);
            queue.push_back(location.into());
        }
        None => {
            let location = il::RefFunctionLocation::EmptyBlock(entry_block);
            let location = il::RefProgramLocation::new(function, location);
            queue.push_back(location.into());
        }
    }

    let mut steps = 0;

    while !queue.is_empty() {
        if steps > max_analysis_steps {
            return Err(Error::FixedPointMaxSteps);
        }
        steps += 1;

        let location = queue.pop_front().unwrap();

        // TODO this should not be an unwrap
        let location = location.function_location().apply(function).unwrap();

        let location = il::RefProgramLocation::new(function, location);

        let location_predecessors = location.backward()?;

        let state =
            location_predecessors
                .into_iter()
                .fold(None, |s, p| match states.get(&p.into()) {
                    Some(in_state) => match s {
                        Some(s) => Some(analysis.join(s, in_state).unwrap()),
                        None => Some(in_state.clone()),
                    },
                    None => s,
                });

        let mut state = analysis.trans(location.clone(), state)?;

        if let Some(in_state) = states.get(&location.clone().into()) {
            let ordering = match state.partial_cmp(in_state) {
                Some(ordering) => match ordering {
                    ::std::cmp::Ordering::Less => Some("less"),
                    ::std::cmp::Ordering::Equal => {
                        continue;
                    }
                    ::std::cmp::Ordering::Greater => None,
                },
                None => Some("no relation"),
            };
            if force {
                state = analysis.join(state, in_state)?;
            } else if let Some(ordering) = ordering {
                return Err(Error::FixedPointOrdering(
                    ordering.to_string(),
                    location.into(),
                ));
            }
        }

        states.insert(location.clone().into(), state);

        for successor in location.forward()? {
            if !queue.contains(&successor.clone().into()) {
                queue.push_back(successor.into());
            }
        }
    }

    Ok(states)
}

/// A guaranteed sound analysis, which enforces the partial order over states.
pub fn fixed_point_forward<'f, Analysis, State>(
    analysis: Analysis,
    function: &'f il::Function,
) -> Result<HashMap<il::ProgramLocation, State>, Error>
where
    Analysis: FixedPointAnalysis<'f, State>,
    State: 'f + Clone + Debug + PartialOrd,
{
    fixed_point_forward_options(analysis, function, false, DEFAULT_MAX_ANALYSIS_STEPS)
}

/// A backward, work-list data-flow analysis algorithm.
///
/// When force is true, the partial order over inputs is forced by joining
/// states which do not inherently enforce the partial order.
pub fn fixed_point_backward_options<'f, Analysis, State>(
    analysis: Analysis,
    function: &'f il::Function,
    force: bool,
) -> Result<HashMap<il::RefProgramLocation<'f>, State>, Error>
where
    Analysis: FixedPointAnalysis<'f, State>,
    State: 'f + Clone + Debug + PartialOrd,
{
    let mut states: HashMap<il::RefProgramLocation<'f>, State> = HashMap::new();

    let mut queue: VecDeque<il::RefProgramLocation<'f>> = VecDeque::new();

    // Find the exit block to the function.
    let exit_index = function
        .control_flow_graph()
        .exit()
        .ok_or(Error::FixedPointRequiresExit)?;
    let exit_block = function.control_flow_graph().block(exit_index)?;

    match exit_block.instructions().last() {
        Some(instruction) => {
            let location = il::RefFunctionLocation::Instruction(exit_block, instruction);
            let location = il::RefProgramLocation::new(function, location);
            queue.push_back(location.clone());
        }
        None => {
            let location = il::RefFunctionLocation::EmptyBlock(exit_block);
            let location = il::RefProgramLocation::new(function, location);
            queue.push_back(location.clone());
        }
    }

    while !queue.is_empty() {
        let location = queue.pop_front().unwrap();

        let location_successors = location.forward()?;

        let state = location_successors
            .iter()
            .fold(None, |s, p| match states.get(p) {
                Some(in_state) => match s {
                    Some(s) => Some(analysis.join(s, in_state).unwrap()),
                    None => Some(in_state.clone()),
                },
                None => s,
            });

        let mut state = analysis.trans(location.clone(), state)?;

        if let Some(in_state) = states.get(&location) {
            let ordering = match state.partial_cmp(in_state) {
                Some(ordering) => match ordering {
                    ::std::cmp::Ordering::Less => Some("less"),
                    ::std::cmp::Ordering::Equal => {
                        continue;
                    }
                    ::std::cmp::Ordering::Greater => None,
                },
                None => Some("no relation"),
            };
            if force {
                state = analysis.join(state, in_state)?;
            } else if let Some(ordering) = ordering {
                return Err(Error::FixedPointOrdering(
                    ordering.to_string(),
                    location.into(),
                ));
            }
        }

        states.insert(location.clone(), state);

        for successor in location.backward()? {
            if !queue.contains(&successor) {
                queue.push_back(successor);
            }
        }
    }

    Ok(states)
}

/// A guaranteed sound analysis, which enforces the partial order over states.
pub fn fixed_point_backward<'f, Analysis, State>(
    analysis: Analysis,
    function: &'f il::Function,
) -> Result<HashMap<il::RefProgramLocation<'f>, State>, Error>
where
    Analysis: FixedPointAnalysis<'f, State>,
    State: 'f + Clone + Debug + PartialOrd,
{
    fixed_point_backward_options(analysis, function, false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::il;

    /// A trivial backward analysis that counts how many locations it visits.
    /// The state is just a counter (usize) that increments at each location.
    struct CountingAnalysis;

    impl<'f> FixedPointAnalysis<'f, usize> for CountingAnalysis {
        fn trans(
            &self,
            _location: il::RefProgramLocation<'f>,
            state: Option<usize>,
        ) -> Result<usize, Error> {
            Ok(state.unwrap_or(0) + 1)
        }

        fn join(&self, state0: usize, state1: &usize) -> Result<usize, Error> {
            Ok(std::cmp::max(state0, *state1))
        }
    }

    #[test]
    fn backward_analysis_starts_from_exit() {
        // Bug: fixed_point_backward uses .entry() instead of .exit(),
        // causing backward analysis to start from the wrong block.
        //
        // Build: entry_block(nop) -> exit_block(nop)
        // Set both entry and exit on the CFG.
        // Run backward analysis.
        // The analysis should visit at least the exit block's instruction.
        // With the bug (.entry()), the analysis starts from entry which has
        // no predecessors in backward traversal, so it only visits entry.
        // With the fix (.exit()), it starts from exit and walks backward to entry.
        let mut cfg = il::ControlFlowGraph::new();

        let entry_index = {
            let block = cfg.new_block().unwrap();
            block.nop();
            block.index()
        };

        let exit_index = {
            let block = cfg.new_block().unwrap();
            block.nop();
            block.index()
        };

        cfg.unconditional_edge(entry_index, exit_index).unwrap();
        cfg.set_entry(entry_index).unwrap();
        cfg.set_exit(exit_index).unwrap();

        let function = il::Function::new(0, cfg);

        let states = fixed_point_backward(CountingAnalysis, &function).unwrap();

        // The exit block's instruction should have been visited
        let exit_block = function.control_flow_graph().block(exit_index).unwrap();
        let exit_instruction = exit_block.instructions().first().unwrap();
        let exit_location = il::RefProgramLocation::new(
            &function,
            il::RefFunctionLocation::Instruction(exit_block, exit_instruction),
        );

        assert!(
            states.contains_key(&exit_location),
            "Backward analysis should visit the exit block, but it was not found in states. \
             This indicates the analysis started from the wrong block (entry instead of exit)."
        );
    }
}
