pub use analysis::analysis_location::*;
use error::*;
use il;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt::Debug;


pub trait FixedPointAnalysis<State: Clone + Debug + PartialEq + Eq> {
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


/// Holds the initial state for a fixed-point analysis, before any analysis
/// has been conducted.
///
/// Allows us to spend a decent amount of time preparing for analysis, cache
/// that work, and conduct the actual analysis faster.
struct FPA {
    predecessor_locations: BTreeMap<AnalysisLocation, Vec<AnalysisLocation>>,
    successor_locations: BTreeMap<AnalysisLocation, Vec<AnalysisLocation>>,
    back_edges: BTreeMap<AnalysisLocation, BTreeSet<AnalysisLocation>>
}


impl FPA {
    pub fn new(control_flow_graph: &il::ControlFlowGraph) -> Result<FPA> {
        let mut predecessor_locations = BTreeMap::new();
        let mut successor_locations = BTreeMap::new();

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
            }

            for instruction in block.instructions() {
                // Location for this instruction
                let analysis_location = AnalysisLocation::instruction(
                    block.index(),
                    instruction.index()
                );

                // Set predecessors
                predecessor_locations.insert(analysis_location.clone(), predlocs);

                // predlocs is now just this analysis_location
                predlocs = Vec::new();
                predlocs.push(analysis_location.clone());

                // Initialize successor_locations
                successor_locations.insert(analysis_location.clone(), Vec::new());
            }

            // handle empty blocks
            if block.instructions().is_empty() {
                let analysis_location = AnalysisLocation::empty_block(block.index());

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

        // Create a mapping of analysis_location to all the predecessor
        // analysis_locations. We do this to properly order our analysis.
        let back_edges = {
            let mut back_edges = BTreeMap::new();
            let mut back_edge_queue: VecDeque<&AnalysisLocation> = VecDeque::new();
            trace!("initializing back_edges");
            for entry in &predecessor_locations {
                let al = entry.0;
                let preds = entry.1
                                 .iter()
                                 .cloned()
                                 .collect::<BTreeSet<AnalysisLocation>>();
                back_edges.insert(al.clone(), preds);
                back_edge_queue.push_back(al);
            }

            // See the implementation in Graph::compute_predecessors for notes on this
            // algorithm
            trace!("populating back_edges");
            trace!("back_edges.len()={}", back_edges.len());
            let mut iterations = 0;
            while !back_edge_queue.is_empty() {
                let al = back_edge_queue.pop_front().unwrap();

                let mut to_add = Vec::with_capacity(back_edges.len());
                {
                    let this_predecessors = &back_edges[al];
                    for predecessor in &predecessor_locations[al] {
                        for pp in &back_edges[predecessor] {
                            iterations += 1;
                            if !this_predecessors.contains(pp) {
                                to_add.push(pp.clone());
                            }
                        }
                    }
                }

                if !to_add.is_empty() {
                    for successor in &successor_locations[al] {
                        back_edge_queue.push_back(successor);
                    }
                }

                let mut this_predecessors = back_edges.get_mut(al).unwrap();
                for predecessor in to_add {
                    this_predecessors.insert(predecessor);
                }

            }
            trace!("iterations={}", iterations);

            back_edges
        };

        // back_edges now contains all predecessors for each analysis_location.
        // We will now prune this so that back_edges contains predecessors for an
        // analysis_location only if that predecessor also contains the
        // analysis_location in back_edges. This will cause back_edges to contain,
        // for each analysis_location, a set of all analysis_locations which are
        // reachable through a back edge.
        trace!("pruning back_edges");
        let back_edges = {
            let mut pruned_sets = BTreeMap::new();
            for back_edge in &back_edges {
                let al = back_edge.0;
                let set = back_edge.1;
                let mut pruned_set = BTreeSet::new();
                for pred in set {
                    if back_edges[pred].contains(al) {
                        pruned_set.insert(pred.clone());
                    }
                }
                pruned_sets.insert(al.clone(), pruned_set);
            }
            pruned_sets
        };

        Ok(FPA {
            predecessor_locations: predecessor_locations,
            successor_locations: successor_locations,
            back_edges: back_edges
        })
    }
}



pub fn fixed_point_forward<Analysis, State>(
    analysis: &Analysis,
    control_flow_graph: &il::ControlFlowGraph
)-> Result<BTreeMap<AnalysisLocation, State>> 
where Analysis: FixedPointAnalysis<State>, State: Clone + Debug + PartialEq + Eq {

    let mut states: BTreeMap<AnalysisLocation, State> = BTreeMap::new();
    let mut queue: VecDeque<AnalysisLocation> = VecDeque::new();

    let fpa = FPA::new(control_flow_graph)?;

    for al in fpa.back_edges.keys() {
        queue.push_back(al.clone());
    }

    // for every instruction in the queue
    while !queue.is_empty() {
        let analysis_location = queue.pop_front().unwrap();

        let predlocs = match fpa.predecessor_locations.get(&analysis_location) {
            Some(predlocs) => predlocs,
            None => bail!(
                "failed to get predecessor_locations for {}",
                analysis_location
            )
        };

        // join states of the last instruction of all predecessors to this block
        let out_state = {
            let mut in_state = None;
            for analysis_location in predlocs {
                if let Some(state) = states.get(analysis_location) {
                    if let Some(in_state_) = in_state {
                        in_state = Some(analysis.join(in_state_, state)?);
                    }
                    else {
                        in_state = Some(state.clone());
                    }
                }
            }

            analysis.trans(&analysis_location, &in_state)?
        };

        if let Some(in_state) = states.get(&analysis_location) {
            if out_state == *in_state {
                // If we have successors reachable via back edges, we add all
                // successors not reachable by back edges
                if fpa.back_edges[&analysis_location].is_empty() {
                    continue;
                }
                for successor_location in &fpa.successor_locations[&analysis_location] {
                    if    !fpa.back_edges[&analysis_location].contains(successor_location)
                       && !queue.contains(successor_location) {
                        queue.push_back(successor_location.clone());
                    }
                }
                continue;
            }
        }

        states.insert(analysis_location.clone(), out_state);

        // If we have successors reachable via back edges, we only add
        // those successors
        if !fpa.back_edges[&analysis_location].is_empty() {
            for successor_location in &fpa.successor_locations[&analysis_location] {
                if    fpa.back_edges[&analysis_location].contains(successor_location)
                   && !queue.contains(successor_location) {
                    queue.push_back(successor_location.clone());
                }
            }
        }
        // If we don't have any back edges, we add all successors
        else {
            for successor_location in &fpa.successor_locations[&analysis_location] {
                if !queue.contains(successor_location) {
                    queue.push_back(successor_location.clone());
                }
            }
        }
    }

    Ok(states)
}



pub fn fixed_point_backward<Analysis, State>(
    analysis: &Analysis,
    control_flow_graph: &il::ControlFlowGraph
)-> Result<BTreeMap<AnalysisLocation, State>> 
where Analysis: FixedPointAnalysis<State>, State: Clone + Debug + PartialEq + Eq {

    let mut states: BTreeMap<AnalysisLocation, State> = BTreeMap::new();
    let mut queue: VecDeque<AnalysisLocation> = VecDeque::new();

    let fpa = FPA::new(control_flow_graph)?;

    for al in fpa.back_edges.keys() {
        queue.push_back(al.clone());
    }

    // for every instruction in the queue
    while !queue.is_empty() {
        let analysis_location = queue.pop_front().unwrap();

        let succlocs = match fpa.successor_locations.get(&analysis_location) {
            Some(succlocs) => succlocs,
            None => bail!(
                "failed to get predecessor_locations for {}",
                analysis_location
            )
        };

        // join states of the successors to this block
        let out_state = {
            let mut in_state = None;
            for analysis_location in succlocs {
                if let Some(state) = states.get(analysis_location) {
                    if let Some(in_state_) = in_state {
                        in_state = Some(analysis.join(in_state_, state)?);
                    }
                    else {
                        in_state = Some(state.clone());
                    }
                }
            }

            analysis.trans(&analysis_location, &in_state)?
        };

        if let Some(in_state) = states.get(&analysis_location) {
            if out_state == *in_state {
                continue;
            }
        }

        info!("adding predecessors");

        states.insert(analysis_location.clone(), out_state);

        for predecessor_location in &fpa.predecessor_locations[&analysis_location] {
            if !queue.contains(predecessor_location) {
                queue.push_back(predecessor_location.clone());
            }
        }
    }

    Ok(states)
}
