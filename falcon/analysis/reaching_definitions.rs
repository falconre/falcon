use analysis::fixed_point::*;
use error::*;
use il::*;
use std::collections::{BTreeMap, BTreeSet};



type Reaches = BTreeSet<InstructionLocation>;


pub fn reaches_to_string(reaches: &Reaches) -> String {
    reaches.iter()
        .map(|il| format!("{}", il))
        .collect::<Vec<String>>()
        .join(",")
}


pub fn reaches_to_string_with_var(
    reaches: &Reaches,
    control_flow_graph: &ControlFlowGraph
) -> Result<String> {
    let mut strings = Vec::new();
    for reach in reaches {
        strings.push(format!(
            "({}-{})",
            reach,
            reach.find(control_flow_graph)?
                 .variable_written()
                 .unwrap()
        ));
    }
    Ok(strings.join(","))
}


pub fn compute(control_flow_graph: &ControlFlowGraph)
-> Result<BTreeMap<InstructionLocation, Reaches>> {
    let reaching_definitions = ReachingDefinitions::new(control_flow_graph);
    reaching_definitions.compute()
}


struct ReachingDefinitions<'a> {
    control_flow_graph: &'a ControlFlowGraph
}


impl<'a> ReachingDefinitions<'a> {
    pub fn new(control_flow_graph: &'a ControlFlowGraph) -> ReachingDefinitions<'a> {
        ReachingDefinitions {
            control_flow_graph: control_flow_graph
        }
    }

    pub fn compute(&self) -> Result<BTreeMap<InstructionLocation, Reaches>> {
        fixed_point(self)
    }
}



impl<'f> FixedPointAnalysis<Reaches> for ReachingDefinitions<'f> {
    fn initial(&self, instruction_location: &InstructionLocation) -> Result<Reaches> {
        Ok(BTreeSet::new())
    }


    fn trans(
        &self,
        instruction_location: &InstructionLocation,
        in_state: &Option<Reaches>
    ) -> Result<Reaches> {

        // Copy in state to out state
        let mut out_state = match in_state {
            &Some(ref in_state) => {
                in_state.clone()
            }
            &None => BTreeSet::new()
        };

        if let Some(this_dst) = instruction_location.find(self.control_flow_graph)?
                                                    .variable_written() {
            // If we kill anything in in_state, remove it
            if let &Some(ref in_state) = in_state {
                for kill_location in in_state {
                    if let Some(dst) = kill_location.find(self.control_flow_graph)?
                                                           .variable_written() {
                        if this_dst.name() == dst.name() {
                            out_state.remove(&kill_location);
                        }
                    }
                }
            }

            // Add this location to out_state
            out_state.insert(instruction_location.clone());
        }

        Ok(out_state)
    }


    fn join(&self, state0: &Reaches, state1: &Reaches) -> Result<Reaches> {
        let mut state = state0.clone();
        for s in state1 {
            state.insert(s.clone());
        }
        Ok(state)
    }


    fn control_flow_graph(&self) -> &ControlFlowGraph {
        &self.control_flow_graph
    }
}