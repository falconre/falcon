//! Applies Static Single Assignment to the `il::ControlFlowGraph`, inserting
//! intermediate blocks with Phi instructions as required.

use error::*;
use graph;
use il;
use il::Variable;
use std::collections::{BTreeMap, BTreeSet, VecDeque};

pub fn ssa(mut control_flow_graph: il::ControlFlowGraph) -> Result<il::ControlFlowGraph> {
    if control_flow_graph.entry().is_none() {
        bail!("no entry vertex set for ControlFlowGraph");
    }

    control_flow_graph = clear_ssa(control_flow_graph)?;

    struct CfgAssigner {
        assignments: BTreeMap<String, u32>
    }

    impl CfgAssigner {
        pub fn new() -> CfgAssigner {
            CfgAssigner { assignments: BTreeMap::new() }
        }

        pub fn get<S: Into<String>>(&mut self, name: S) -> u32 {
            let n: String = name.into();
            if !self.assignments.contains_key(&n) {
                self.assignments.insert(n.clone(), 0);
            }
            self.assignments[&n]
        }

        pub fn set<S: Into<String>>(&mut self, name: S) -> u32 {
            let n: String = name.into();
            let current_value = self.get(n.clone());
            self.assignments.insert(n.clone(), current_value + 1);
            current_value + 1
        }
    }

    // Applies SSA internally to a block, leaving ssa unset for any
    // variables which are not set in the same block.
    fn ssa_block(block: &mut il::Block, assigner: &mut CfgAssigner) {
        let mut block_set: BTreeMap<String, u32> = BTreeMap::new();

        for operation in block.instructions_mut() {
            for variable in operation.variables_read_mut() {
                if block_set.contains_key(variable.name()) {
                    let name = variable.name().to_owned();
                    variable.set_ssa(Some(block_set[&name]));
                }
            }
            if let Some(mut variable) = operation.variable_written_mut() {
                if variable.ssa().is_none() {
                    let name = variable.name().to_owned();
                    variable.set_ssa(Some(assigner.set(name)));
                }
                block_set.insert(
                    variable.name().to_owned(),
                    variable.ssa().unwrap()
                );
            }
        }
    }

    // Returns the ssa values for all variable assignments on block exit
    // This should be called after ssa block, and all written variables
    // should have SSA assignments.
    fn get_block_ssa_assignments(block: &il::Block) -> BTreeMap<&str, &il::Variable> {
        let mut assignments: BTreeMap<&str, &il::Variable> = BTreeMap::new();

        for operation in block.instructions() {
            if let Some(variable) = operation.variable_written() {
                assignments.insert(
                    variable.name(),
                    variable
                );
            }
        }

        assignments
    }

    // Returns a vector of all variables without SSA set on exit
    fn get_block_ssa_unassigned(block: &il::Block) -> Vec<il::MultiVar> {
        let mut unassigned: Vec<il::MultiVar> = Vec::new();

        for operation in block.instructions() {
            for variable in operation.variables_read() {
                if variable.ssa().is_none() && !unassigned.contains(&variable.multi_var_clone()) {
                    unassigned.push(variable.multi_var_clone());
                }
            }
        }

        unassigned
    }

    fn find_assignments(
        block: &il::Block,
        mut unassigned: Vec<il::MultiVar>,
        mut visited: BTreeSet<u64>,
        graph: &graph::Graph<il::Block, il::Edge>,
    ) -> Result<BTreeMap<String, BTreeSet<u32>>> {

        let mut found: BTreeMap<String, BTreeSet<u32>> = BTreeMap::new();

        // This allows us to specify whether or not to skip the first
        // block before calling this function, and use it for blocks
        // and edges
        if !visited.contains(&block.index()) {
            let assignments = get_block_ssa_assignments(block);

            let mut found_this_block = Vec::new();

            for una in unassigned.clone() {
                if assignments.get(una.name()).is_some() {
                    if !found.contains_key(una.name()) {
                        found.insert(una.name().to_string(), BTreeSet::new());
                    }
                    found.get_mut(una.name())
                         .unwrap()
                         .insert(assignments[una.name()].ssa().unwrap());
                    found_this_block.push(una);
                }
            }

            for ftb in found_this_block {
                unassigned.iter()
                          .position(|n| *n == ftb)
                          .map(|e| unassigned.remove(e));
            }
            visited.insert(block.index());
        }

        if !unassigned.is_empty() {
            for predecessor in graph.predecessors(block.index())? {
                if visited.contains(&predecessor.index()) {
                    continue;
                }
                let block_found = find_assignments(
                    predecessor,
                    unassigned.clone(),
                    visited.clone(),
                    graph
                )?;
                for bf in block_found {
                    if !found.contains_key(&bf.0) {
                        found.insert(bf.0.clone(), BTreeSet::new());
                    }
                    for s in bf.1 {
                        let mut found_set = found.get_mut(&bf.0).unwrap();
                        found_set.insert(s);
                    }
                }
            }
        }

        Ok(found)
    }

    // keeps track of SSA assignments globally across the ControlFlowGraph
    let mut assigner = CfgAssigner::new();

    // We apply SSA to each block
    for block in control_flow_graph.blocks_mut() {
        ssa_block(block, &mut assigner);
    }

    // For every block where SSA is not set, we recursively search
    // backwards for the earliest occurences where the variable was set.
    // We always make sure the block's predecessors, according to a DAG,
    // are set before we process this block.
    // One of three cases will take place:
    // No occurences were found =>
    //     We leave this variable alone
    // One SSA occurence was found =>
    //     We use the SSA value of this occurence
    // More than one SSA occurence was found =>
    //     We create a Phi operation assigning these two a new variable
    //     with a new SSA, and prepend this Phi to the beginning of the
    //     block

    let mut queue = VecDeque::new();
    queue.push_back(control_flow_graph.entry().unwrap());

    let dag = control_flow_graph.graph()
                                .compute_acyclic(control_flow_graph.entry()
                                                                   .unwrap())?;
    let mut ssa_set: BTreeSet<u64> = BTreeSet::new();

    while !queue.is_empty() {
        let block_index = queue.pop_front().unwrap();

        // ensure all predecessors are set according to DAG
        let mut predecessors_set = true;
        for edge in dag.edges_in(block_index)? {
            let head = graph::Edge::head(edge);
            if !ssa_set.contains(&head) {
                if !queue.contains(&head) {
                    queue.push_back(head);
                }
                predecessors_set = false;
            }
        }

        if !predecessors_set {
            queue.push_back(block_index);
            continue;
        }

        // all predecessors set
        ssa_set.insert(block_index);

        let (found, unassigned) = {
            let block = control_flow_graph.block(block_index)?;

            let unassigned = get_block_ssa_unassigned(block); 

            let mut visited = BTreeSet::new();
            visited.insert(block.index());

            let found = find_assignments(
                block,
                unassigned.clone(),
                visited,
                control_flow_graph.graph()
            )?;
            (found, unassigned)
        };

        for una in &unassigned {
            if let Some(assignments) = found.get(una.name()) {
                if assignments.len() == 1 {
                    let block = control_flow_graph.block_mut(block_index)?;
                    for ref mut operation in block.instructions_mut() {
                        for ref mut variable in operation.variables_read_mut() {
                            if    variable.name() == una.name()
                               && variable.ssa() == None {
                                variable.set_ssa(Some(*assignments.iter()
                                                                  .next()
                                                                  .unwrap()));
                            }
                        }
                    }
                }
                else {
                    let mut dst = una.clone();
                    dst.set_ssa(Some(assigner.get(una.name())));
                    let mut src = Vec::new();
                    for assignment in assignments.iter() {
                        let mut var = una.clone();
                        var.set_ssa(Some(*assignment));
                        src.push(var);
                    }
                    control_flow_graph.block_mut(block_index)?
                                      .prepend_phi(
                                        dst.multi_var_clone(),
                                        src.iter()
                                           .map(|v| v.multi_var_clone())
                                           .collect::<Vec<il::MultiVar>>()
                                      );
                }
            }
        }

        // add all successors to the queue
        for edge in control_flow_graph.graph().edges_out(block_index)? {
            if !ssa_set.contains(&edge.tail()) && !queue.contains(&edge.tail()) {
                queue.push_back(edge.tail());
            }
        }
    }

    // Every block should now have an ssa assignment in it for all
    // variable writes. We go back and make sure all reads are good to go.
    for mut block in control_flow_graph.blocks_mut() {
        ssa_block(block, &mut assigner);
    }
    
    let edges = { 
        control_flow_graph.graph()
                          .edges()
                          .iter()
                          .map(|e| (*e).clone()).collect::<Vec<il::Edge>>()
    };

    for edge in edges {
        if edge.condition().is_none() {
            continue;
        }

        let unassigned: Vec<il::MultiVar> = edge.condition()
                                                .clone()
                                                .unwrap()
                                                .collect_variables()
                                                .iter()
                                                .map(|v| v.multi_var_clone())
                                                .collect();

        let found = find_assignments(
            control_flow_graph.graph().vertex(edge.head())?,
            unassigned,
            BTreeSet::new(),
            control_flow_graph.graph()
        )?;


        let block_index = edge.head();

        // Assign SSA to edges
        let mut phis_to_add: Vec<(u64, il::MultiVar, Vec<il::MultiVar>)> = Vec::new();

        {
            let mut edge = control_flow_graph.edge_mut(edge.head(), edge.tail())?;

            if let Some(ref mut condition) = *edge.condition_mut() {
                for scalar in condition.collect_scalars_mut() {
                    if let Some(assignments) = found.get(scalar.name()) {
                        if assignments.len() == 1 {
                            scalar.set_ssa(Some(*assignments.iter()
                                                            .next()
                                                            .unwrap()));
                            continue;
                        }
                        let mut dst = scalar.clone();
                        dst.set_ssa(Some(assigner.get(scalar.name())));
                        scalar.set_ssa(Some(dst.ssa().unwrap()));
                        let mut src = Vec::new();
                        for assignment in assignments.iter() {
                            let mut var = scalar.clone();
                            var.set_ssa(Some(*assignment));
                            src.push(var.multi_var_clone());
                        }
                        phis_to_add.push((
                            block_index,
                            dst.multi_var_clone(),
                            src
                        ));
                    }
                }
            }
        }
        
        for phi_to_add in phis_to_add {
            control_flow_graph.block_mut(phi_to_add.0)?
                              .phi(phi_to_add.1, phi_to_add.2);
        }
    }

    Ok(control_flow_graph)
}




pub fn clear_ssa(mut control_flow_graph: il::ControlFlowGraph)
-> Result<il::ControlFlowGraph> {
    for block in control_flow_graph.blocks_mut() {
        let mut phi_indices = Vec::new();
        for instruction in block.instructions_mut() {
            if let il::Operation::Phi{..} = *instruction.operation() {
                phi_indices.push(instruction.index());
                continue;
            }
            for variable in instruction.variables_read_mut() {
                variable.set_ssa(None);
            }
            if let Some(mut variable) = instruction.variable_written_mut() {
                variable.set_ssa(None);
            }
        }
        for phi_index in phi_indices {
            block.remove_instruction(phi_index)?;
        }
    }

    for edge in control_flow_graph.edges_mut() {
        let condition = edge.condition_mut();
        if let Some(ref mut condition) = *condition {
            for scalar in condition.collect_scalars_mut() {
                scalar.set_ssa(None);
            }
        }
    }

    Ok(control_flow_graph)
}