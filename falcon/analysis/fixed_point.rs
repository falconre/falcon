use error::*;
use il::{Block, ControlFlowGraph};
use std::collections::{HashMap, VecDeque};
use std::ops::Deref;


pub trait FixedPointAnalysis<State: PartialEq> {
    /// Create an initial state for a block.
    fn initial(block: &Block) -> State;

    /// Given an input state for a block, create an output state for this
    /// block.
    fn trans(block: &Block, state: &State) -> State;

    /// Given two states, join them into one state.
    fn join(state0: &State, state1: &State) -> State;
}


pub fn fixed_point<Analysis, State>(control_flow_graph: &ControlFlowGraph) 
-> Result<HashMap<u64, State>> where Analysis: FixedPointAnalysis<State>, State: PartialEq {
    let mut states: HashMap<u64, State> = HashMap::new();
    let mut queue: VecDeque<u64> = VecDeque::new();

    // fill with initial states, and all blocks to the queue
    for block in control_flow_graph.blocks().iter() {
        states.insert(block.index(), Analysis::initial(&block));
        queue.push_back(block.index());
    }

    // start with all vertices in the queue
    while queue.len() > 0 {
        let vertex_index = queue.pop_front().unwrap();

        let state = Analysis::trans(
            control_flow_graph.block(vertex_index)?.deref(),
            states.get(&vertex_index).unwrap()
        );
        if state != *states.get(&vertex_index).unwrap() {
            states.insert(vertex_index, state);
            for edge in control_flow_graph.graph().edges_out(vertex_index)? {
                queue.push_back(edge.tail());
            }
        }
    }

    Ok(states)
}