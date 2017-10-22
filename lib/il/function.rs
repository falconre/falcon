//! A `Function` holds a `ControlFlowGraph`.
//!
//! We can think of a `Function` as providing _location_ to a `ControlFlowGraph`.

use il::*;


/// A function for Falcon IL. Provides location and context in a `Program` to a
/// `ControlFlowGraph`.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct Function {
    // The address where this function was found
    address: u64,
    // The `ControlFlowGraph` capturing semantics of the function
    control_flow_graph: ControlFlowGraph,
    // The name of the function
    name: Option<String>,
    // Functions which belong to Programs have indices
    index: Option<u64>
}


impl Function {
    /// Create a new `Function`
    ///
    /// # Parameters
    /// * `address` - The address where we recovered this function.
    /// * `control_flow_graph` - A `ControlFlowGraph` capturing the semantics of this function.
    pub fn new(address: u64, control_flow_graph: ControlFlowGraph) -> Function {
        Function {
            address: address,
            control_flow_graph: control_flow_graph,
            name: None,
            index: None
        }
    }

    /// Get the address of this `Function`.
    ///
    /// The address returned will be the address set when this `Function` was created,
    /// which should be the virtual address where this `Function` was found.
    pub fn address(&self) -> u64 {
        self.address
    }

    /// Return a `Block` from this `Function`'s `ControlFlowGraph` by index.
    pub fn block(&self, index: u64) -> Option<&Block> {
        self.control_flow_graph.block(index)
    }

    /// Return a vec of all `Block` in this `Function`
    pub fn blocks(&self) -> Vec<&Block> {
        self.control_flow_graph.blocks()
    }

    /// Return an `Edge` from this `Function`'s `ControlFlowGraph` by index.
    pub fn edge(&self, head: u64, tail: u64) -> Option<&Edge> {
        self.control_flow_graph.edge(head, tail)
    }

    /// Return a vec of all `Edge` in this `Function`
    pub fn edges(&self) -> Vec<&Edge> {
        self.control_flow_graph.edges()
    }

    /// Return the `ControlFlowGraph` for this `Function`.
    pub fn control_flow_graph(&self) -> &ControlFlowGraph {
        &self.control_flow_graph
    }

    /// Return a mutable reference to the `ControlFlowGraph` for this `Function`.
    pub fn control_flow_graph_mut(&mut self) -> &mut ControlFlowGraph {
        &mut self.control_flow_graph
    }

    /// Return the name of this `Function`.
    pub fn name(&self) -> String {
        match self.name {
            Some(ref name) => name.to_string(),
            None => format!("unknown@{:08X}", self.address)
        }
    }

    /// Set this `Function`'s name.
    pub fn set_name(&mut self, name: Option<String>) {
        self.name = name;
    }

    /// Return the index of this `Function`. A `Function` will have an index if
    /// it is added to a `Program`.
    pub fn index(&self) -> Option<u64> {
        self.index
    }


    pub(crate) fn set_index(&mut self, index: Option<u64>) {
        self.index = index;
    }
}