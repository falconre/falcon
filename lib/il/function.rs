use il::*;


#[derive(Clone, Debug, Deserialize, Serialize)]
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
    pub fn new(address: u64, control_flow_graph: ControlFlowGraph) -> Function {
        Function {
            address: address,
            control_flow_graph: control_flow_graph,
            name: None,
            index: None
        }
    }


    pub fn address(&self) -> u64 {
        self.address
    }


    pub fn block(&self, index: u64) -> Option<&Block> {
        self.control_flow_graph.block(index)
    }


    pub fn edge(&self, head: u64, tail: u64) -> Option<&Edge> {
        self.control_flow_graph.edge(head, tail)
    }


    pub fn control_flow_graph(&self) -> &ControlFlowGraph {
        &self.control_flow_graph
    }


    pub fn control_flow_graph_mut(&mut self) -> &mut ControlFlowGraph {
        &mut self.control_flow_graph
    }


    pub fn name(&self) -> String {
        match self.name {
            Some(ref name) => name.to_string(),
            None => format!("unknown@{:08X}", self.address)
        }
    }


    pub fn set_name(&mut self, name: Option<String>) {
        self.name = name;
    }


    pub fn index(&self) -> Option<u64> {
        self.index
    }


    pub fn set_index(&mut self, index: Option<u64>) {
        self.index = index;
    }
}