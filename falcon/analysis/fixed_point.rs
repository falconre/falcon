pub use analysis::instruction_location::*;
use error::*;
use il::*;
use std::collections::{BTreeMap, VecDeque};


pub trait FixedPointAnalysis<State: PartialEq> {
    /// Create an initial state for a block.
    fn initial(&self, instruction_location: &InstructionLocation) -> Result<State>;

    /// Given an input state for a block, create an output state for this
    /// block.
    fn trans(
        &self,
        instruction_location: &InstructionLocation,
        state: &Option<State>
    ) -> Result<State>;

    /// Given two states, join them into one state.
    fn join(&self, state0: &State, state1: &State) -> Result<State>;

    fn control_flow_graph(&self) -> &ControlFlowGraph;
}



pub fn fixed_point<Analysis, State>(analysis: &Analysis)
-> Result<BTreeMap<InstructionLocation, State>> 
where Analysis: FixedPointAnalysis<State>, State: Clone + PartialEq {

    let mut states: BTreeMap<InstructionLocation, State> = BTreeMap::new();
    let mut predecessor_locations = BTreeMap::new();
    let mut successor_locations = BTreeMap::new();
    let mut queue: VecDeque<InstructionLocation> = VecDeque::new();

    // Fill all initial states.
    // Save the locations of every instruction's predecessors and successors
    // so we don't have to look them up all the time.
    // Add all instructions to the queue for processing.
    for block in analysis.control_flow_graph().blocks() {
        // Find the location_instruction of all predecessors to this block
        let mut predlocs: Vec<InstructionLocation> = Vec::new();

        for predblock in analysis.control_flow_graph()
                                 .graph()
                                 .predecessors(block.index())
                                 .unwrap() {
            if let Some(instruction_location) =  block_last_instruction_location(predblock) {
                predlocs.push(instruction_location);
            }
         }

        for instruction in block.instructions() {
            // Location for this instruction
            let instruction_location = InstructionLocation::new(
                block.index(),
                instruction.index()
            );

            // Insert into states
            states.insert(
                instruction_location.clone(),
                analysis.initial(&instruction_location)?
            );

            // Set predecessors
            predecessor_locations.insert(instruction_location.clone(), predlocs);

            // predlocs is now just this instruction_location
            predlocs = Vec::new();
            predlocs.push(instruction_location.clone());

            // Initialize successor_locations
            successor_locations.insert(instruction_location.clone(), Vec::new());

            // Add this instruction_location to the queue for processing
            queue.push_back(instruction_location);
        }
    }

    // Set all successor_locations based on predecessor_locations
    for entry in &predecessor_locations {
        let successor_location = entry.0;
        for predecessor_location in entry.1 {
            successor_locations.get_mut(&predecessor_location)
                               .unwrap()
                               .push(successor_location.clone());
        }
    }


    // for every instruction in the queue
    while queue.len() > 0 {
        let instruction_location = queue.pop_front().unwrap();

        let ref predlocs = predecessor_locations[&instruction_location];

        // join states of the last instruction of all predecessors to this block
        let out_state = {
            let in_state = match predlocs.len() {
                0 => None,
                1 => Some(states[predlocs.first().unwrap()].clone()),
                _ => {
                    let mut state = states[&predlocs.first().unwrap()].clone();
                    for instruction_location in predlocs {
                        state = analysis.join(&state, &states[instruction_location])?;
                    }
                    Some(state)
                }
            };

            let out_state = analysis.trans(
                &instruction_location,
                &in_state
            )?;

            out_state
        };

        if out_state == states[&instruction_location] {
            continue;
        }

        states.insert(instruction_location.clone(), out_state);
        for successor_location in &successor_locations[&instruction_location] {
            if !queue.contains(&successor_location) {
                queue.push_back(successor_location.clone());
            }
        }
    }

    Ok(states)
}