pub use analysis::analysis_location::*;
use error::*;
use il;
use std::collections::{BTreeMap, VecDeque};
use std::fmt::Debug;


pub trait FixedPointAnalysis<State: Clone + Debug + PartialEq + Eq> {
    /// Create an initial state for a block.
    fn initial(&self, analysis_location: &AnalysisLocation) -> Result<State>;

    /// Given an input state for a block, create an output state for this
    /// block.
    fn trans(
        &self,
        analysis_location: &AnalysisLocation,
        state: &Option<State>
    ) -> Result<State>;

    /// Given two states, join them into one state.
    fn join(&self, state0: State, state1: &State) -> Result<State>;
}



pub fn fixed_point<Analysis, State>(
    analysis: &Analysis,
    control_flow_graph: &il::ControlFlowGraph
)-> Result<BTreeMap<AnalysisLocation, State>> 
where Analysis: FixedPointAnalysis<State>, State: Clone + Debug + PartialEq + Eq {

    let mut states: BTreeMap<AnalysisLocation, State> = BTreeMap::new();
    let mut predecessor_locations = BTreeMap::new();
    let mut successor_locations = BTreeMap::new();
    let mut queue: VecDeque<AnalysisLocation> = VecDeque::new();

    // Fill all initial states.
    // Save the locations of every instruction's predecessors and successors
    // so we don't have to look them up all the time.
    // Add all instructions to the queue for processing.
    for block in control_flow_graph.blocks() {
        // Find the analysis_location of all predecessors to this block
        // These will be edges
        let mut predlocs: Vec<AnalysisLocation> = Vec::new();

        for edge in control_flow_graph.graph()
                                      .edges_in(block.index())? {
            let analysis_location = AnalysisLocation::edge(edge.head(), edge.tail());
            
            // we need an edge from this edge to the last instruction of the
            // head block
            if let Some(ins) = control_flow_graph.block(edge.head())?
                                                 .instructions()
                                                 .last() {
                let mut predlocs = Vec::new();
                predlocs.push(AnalysisLocation::instruction(edge.head(), ins.index()));
                predecessor_locations.insert(analysis_location.clone(), predlocs);
            }
            // If the last block is empty, we need to handle that case as well.
            else {
                let mut predlocs = Vec::new();
                predlocs.push(AnalysisLocation::empty_block(edge.head()));
                predecessor_locations.insert(analysis_location.clone(), predlocs);
            }

            // And an edges from this instruction to the first instruction of
            // the next block, which we prepare here, and initialize state for
            // this instruction.
            predlocs.push(analysis_location.clone());
            successor_locations.insert(analysis_location.clone(), Vec::new());
            states.insert(
                analysis_location.clone(),
                analysis.initial(&analysis_location)?
            );
            queue.push_back(analysis_location.clone());
        }

        for instruction in block.instructions() {
            // Location for this instruction
            let analysis_location = AnalysisLocation::instruction(
                block.index(),
                instruction.index()
            );

            // Insert into states
            states.insert(
                analysis_location.clone(),
                analysis.initial(&analysis_location)?
            );

            // Set predecessors
            predecessor_locations.insert(analysis_location.clone(), predlocs);

            // predlocs is now just this analysis_location
            predlocs = Vec::new();
            predlocs.push(analysis_location.clone());

            // Initialize successor_locations
            successor_locations.insert(analysis_location.clone(), Vec::new());

            // Add this analysis_location to the queue for processing
            queue.push_back(analysis_location);
        }

        // handle empty blocks
        if block.instructions().is_empty() {
            let analysis_location = AnalysisLocation::empty_block(block.index());

            states.insert(
                analysis_location.clone(),
                analysis.initial(&analysis_location)?
            );

            predecessor_locations.insert(analysis_location.clone(), predlocs);

            successor_locations.insert(analysis_location.clone(), Vec::new());
        }
    }

    // Set all successor_locations based on predecessor_locations
    for entry in &predecessor_locations {
        let successor_location = entry.0;
        for predecessor_location in entry.1 {
            match successor_locations.get_mut(predecessor_location) {
                Some(ref mut sl) => sl.push(successor_location.clone()),
                None => bail!(
                    "error processing successor location {}",
                    predecessor_location
                )
            }
        }
    }

    // for every instruction in the queue
    while !queue.is_empty() {
        let analysis_location = queue.pop_front().unwrap();

        let predlocs = match predecessor_locations.get(&analysis_location) {
            Some(predlocs) => predlocs,
            None => bail!(
                "failed to get predecessor_locations for {}",
                analysis_location
            )
        };

        // join states of the last instruction of all predecessors to this block
        let out_state = {
            let in_state = match predlocs.len() {
                0 => None,
                1 => Some(states[predlocs.first().unwrap()].clone()),
                _ => {
                    let mut state = states[predlocs.first().unwrap()].clone();
                    for analysis_location in predlocs {
                        state = analysis.join(state, &states[analysis_location])?;
                    }
                    Some(state)
                }
            };

            analysis.trans(&analysis_location, &in_state)?
        };

        if out_state == states[&analysis_location] {
            continue;
        }

        states.insert(analysis_location.clone(), out_state);

        for successor_location in &successor_locations[&analysis_location] {
            if !queue.contains(successor_location) {
                queue.push_back(successor_location.clone());
            }
        }
    }

    Ok(states)
}