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

    // Find the entry block to the function.
    let exit_index = function
        .control_flow_graph()
        .entry()
        .ok_or(Error::FixedPointRequiresEntry)?;
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
