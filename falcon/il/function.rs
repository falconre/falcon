use il::*;


pub struct Function {
    address: u64,
    control_flow_graph: ControlFlowGraph,
    name: Option<String>
}


impl Function {
    pub fn new(address: u64, control_flow_graph: ControlFlowGraph) -> Function {
        Function {
            address: address,
            control_flow_graph: control_flow_graph,
            name: None
        }
    }


    pub fn address(&self) -> u64 {
        self.address
    }


    pub fn control_flow_graph(&self) -> &ControlFlowGraph {
        &self.control_flow_graph
    }


    pub fn control_flow_graph_mut(&mut self) -> &mut ControlFlowGraph {
        &mut self.control_flow_graph
    }


    pub fn name(&self) -> &Option<String> {
        &self.name
    }


    pub fn set_name(&mut self, name: Option<String>) {
        self.name = name;
    }
}