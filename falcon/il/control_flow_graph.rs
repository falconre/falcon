use std::cell::Cell;
use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;
use il::*;


/// Edge between IL blocks
#[derive(Clone, Debug)]
pub struct Edge {
    head: u64,
    tail: u64,
    condition: Option<Expression>
}


impl Edge {
    pub fn new(head: u64, tail: u64, condition: Option<Expression>) -> Edge {
        Edge {
            head: head,
            tail: tail,
            condition: condition
        }
    }


    pub fn condition(&self) -> &Option<Expression> {
        &self.condition
    }

    pub fn condition_mut(&mut self) -> &mut Option<Expression> {
        &mut self.condition
    }

    pub fn head(&self) -> u64 { self.head }
    pub fn tail(&self) -> u64 { self.tail }
}


impl fmt::Display for Edge {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if self.condition.is_some() {
            return write!(f, "({}->{}) ? ({})", self.head, self.tail, self.condition.clone().unwrap());
        }
        Ok(())
    }
}


impl graph::Edge for Edge {
    fn head(&self) -> u64 { self.head }
    fn tail(&self) -> u64 { self.tail }
    fn dot_label(&self) -> String { format!("{}", self) }
}


impl graph::Vertex for Rc<Block> {
    fn index(&self) -> u64 { self.as_ref().index() }
    fn dot_label(&self) -> String { self.as_ref().dot_label() }
}



impl graph::Edge for Rc<Edge> {
    fn head(&self) -> u64 { self.as_ref().head() }
    fn tail(&self) -> u64 { self.as_ref().tail() }
    fn dot_label(&self) -> String { self.as_ref().dot_label() }
}


/// A graph of IL blocks
#[derive(Clone)]
pub struct ControlFlowGraph {
    // The internal graph used to store our blocks.
    graph: graph::Graph<Block, Edge>,
    // The next index to use when creating a basic block.
    next_index: u64,
    // The index for the next temp variable to create.
    next_temp_index: Cell<u64>,
    // An optional entry index for the graph.
    entry: Option<u64>,
    // An optional exit index for the graph.
    exit: Option<u64>,
    // True if SSA has been applied to the ControlFlowGraph
    ssa_form: bool,
}


impl ControlFlowGraph {
    pub fn new() -> ControlFlowGraph {
        ControlFlowGraph {
            graph: graph::Graph::new(),
            next_index: 0,
            next_temp_index: Cell::new(0),
            entry: None,
            exit: None,
            ssa_form: false,
        }
    }


    /// Returns the underlying graph
    pub fn graph(&self) -> &graph::Graph<Block, Edge> {
        &self.graph
    }


    pub fn set_entry(&mut self, entry: u64) -> Result<()> {
        if self.graph.has_vertex(entry) {
            self.entry = Some(entry);
            return Ok(());
        }
        Err("Index does not exist for set_entry".into())
    }


    pub fn set_exit(&mut self, exit: u64) -> Result<()> {
        if self.graph.has_vertex(exit) {
            self.exit = Some(exit);
            return Ok(());
        }
        Err("Index does not exist for set_exit".into())
    }


    pub fn entry(&self) -> Option<u64> {
        self.entry
    }


    pub fn exit(&self) -> Option<u64> {
        self.exit
    }


    /// Return a block by index
    pub fn block(&self, index: u64) -> Result<&Block> {
        self.graph.vertex(index)
    }


    pub fn block_mut(&mut self, index: u64) -> Result<&mut Block> {
        self.graph.vertex_mut(index)
    }


    /// Returns the entry block for this ControlFlowGraph
    pub fn entry_block(&self) -> Result<Block> {
        if self.entry.is_none() {
            bail!("entry is not set");
        }
        Ok(self.graph.vertex(self.entry.unwrap())?.clone())
    }


    /// Generates a temporary variable unique to this control flow graph.
    pub fn temp(&self, bits: usize) -> Variable {
        let next_index = self.next_temp_index.get();
        self.next_temp_index.set(next_index + 1);
        return Variable::new(format!("temp_{}", next_index), bits);
    }


    /// Get all the blocks in this graph.
    pub fn blocks(&self) -> Vec<&Block> {
        let mut result = Vec::new();
        for vertex in self.graph.vertices() {
            result.push(vertex);
        }
        return result;
    }


    pub fn blocks_mut(&mut self) -> Vec<&mut Block> {
        self.graph.vertices_mut()
    }


    /// Creates a new basic block, adds it to the graph, and returns it
    pub fn new_block(&mut self) -> Result<&mut Block> {
        let next_index = self.next_index;
        self.next_index += 1;
        let block = Block::new(next_index);
        self.graph.insert_vertex(block)?;
        self.graph.vertex_mut(next_index)
    }


    /// Creates an unconditional edge from one block to another block
    pub fn unconditional_edge(&mut self, head: u64, tail: u64) -> Result<()> {
        let edge = Edge::new(head, tail, None);
        self.graph.insert_edge(edge)
    }


    /// Creates a conditional edge from one block to another block
    pub fn conditional_edge(&mut self, head: u64, tail: u64, condition: Expression) -> Result<()> {
        let edge = Edge::new(head, tail, Some(condition));
        self.graph.insert_edge(edge)
    }


    /// Merges all blocks that should be merged
    pub fn merge(&mut self) -> Result<()> {
        loop {
            let mut merge_index = None;
            let mut successor_index = None;
            for block in self.blocks() {
                // check to see how many successors we have
                let successors = self.graph.edges_out(block.index())?;

                // if we do not have just one successor, we will not merge this block
                if successors.len() != 1 {
                    continue;
                }

                // get the vertex for this successor
                let successor: u64 = match successors.first() {
                    Some(successor) => successor.tail(),
                    None => bail!("successor not found")
                };

                // get all predecessors for this successor
                let predecessors = self.graph.edges_in(successor)?;

                // if this successor does not have exactly one predecessor, we
                // will not merge this block
                if predecessors.len() != 1 {
                    continue;
                }

                successor_index = Some(successor);
                merge_index = Some(block.index());
                break;
            }

            // we have a block to merge
            if let Some(merge_index) = merge_index {
                let successor_index = match successor_index {
                    Some(successor_index) => successor_index,
                    None => bail!("merge_index set, but not successor_index")
                };

                // merge the blocks
                let successor_block = self.graph.vertex(successor_index)?.clone();
                self.graph.vertex_mut(merge_index)?.append(&successor_block);

                // all of successor's successors become merge_block's successors
                let mut new_edges = Vec::new();
                for edge in self.graph.edges_out(successor_index)? {
                    let head = merge_index;
                    let tail = edge.tail();
                    let condition = edge.condition().clone();
                    let edge = Edge::new(head, tail, condition);
                    new_edges.push(edge);
                }
                for edge in new_edges {
                    self.graph.insert_edge(edge)?;
                }

                // remove the block we just merged
                self.graph.remove_vertex(successor_index)?;
            } else {
                break;
            }
        }
        Ok(())
    }


    /// Appends a control flow graph to this control flow graph.
    ///
    /// In order for this to work, the entry and exit of boths graphs must be
    /// set, which should be the case for all conformant translators. You can
    /// also append to an empty ControlFlowGraph.
    pub fn append(&mut self, other: &ControlFlowGraph) -> Result<()> {
        let is_empty = match self.graph.num_vertices() {
            0 => true,
            _ => false
        };

        if is_empty == false && (self.entry().is_none() || self.exit().is_none()) {
            return Err("entry/exit not set for dest ControlFlowGraph::append".into());
        }
        
        if other.entry().is_none() || other.exit().is_none() {
            return Err("entry/exit not set for src ControlFlowGraph::append".into());
        }

        // Bring in new blocks
        let mut block_map: HashMap<u64, u64> = HashMap::new();
        for block in other.graph().vertices() {
            // we need to clone the underlying block
            let new_block = block.clone_new_index(self.next_index);
            block_map.insert(block.index(), self.next_index);
            self.next_index += 1;
            self.graph.insert_vertex(new_block)?;
        }

        // Now set all new edges
        for edge in other.graph().edges() {
            let new_head: u64 = *block_map.get(&edge.head()).unwrap();
            let new_tail: u64 = *block_map.get(&edge.tail()).unwrap();
            let new_edge = Edge::new(new_head, new_tail, edge.condition().clone());
            self.graph.insert_edge(new_edge)?;
        }


        if is_empty {
            self.entry = Some(*block_map.get(&other.entry().unwrap()).unwrap());
        }
        else {
            // Create an edge from the exit of this graph to the head of the other
            // graph
            let transition_edge = Edge::new(
                self.exit.unwrap(),
                *block_map.get(&(other.entry().unwrap())).unwrap(),
                None
            );
            self.graph.insert_edge(transition_edge)?;
        }

        self.exit = Some(*block_map.get(&other.exit().unwrap()).unwrap());

        Ok(())
    }

    /// Inserts a control flow graph into this control flow graph, and returns 
    ///
    /// Requires the graph being inserted to have entry set. On success, the
    /// new indices for the other block's entry and exit will be returned. This
    /// will cause the control flow graph to be disconnected.
    ///
    /// # Warnings
    /// This invalidates the entry and exit of the control flow graph.
    pub fn insert(&mut self, other: &ControlFlowGraph) -> Result<(u64, u64)> {
        if other.entry().is_none() || other.exit().is_none() {
            bail!("entry/exit not set on control flow graph");
        }

        // our entry and exit our no longer valid
        self.entry = None;
        self.exit = None;

        // Options to store the other graph entry/exit indices
        let mut entry_index = None;
        let mut exit_index = None;

        // keep track of mapping between old indices and new indices
        let mut block_map: HashMap<u64, u64> = HashMap::new();

        // insert all the blocks
        for block in other.graph().vertices() {
            let new_block = block.clone_new_index(self.next_index);
            block_map.insert(block.index(), self.next_index);
            if block.index() == other.entry().unwrap() {
                entry_index = Some(self.next_index);
            }
            if block.index() == other.exit().unwrap() {
                exit_index = Some(self.next_index);
            }
            self.next_index += 1;
            self.graph.insert_vertex(new_block)?;
        }

        // insert edges
        for edge in other.graph().edges() {
            let new_head: u64 = *block_map.get(&edge.head()).unwrap();
            let new_tail: u64 = *block_map.get(&edge.tail()).unwrap();
            let new_edge = Edge::new(new_head, new_tail, edge.condition().clone());
            self.graph.insert_edge(new_edge)?;
        }

        if entry_index.is_none() || exit_index.is_none() {
            bail!("failed to get entry/exit indices");
        }

        Ok((entry_index.unwrap(), exit_index.unwrap()))
    }


    /// Applies Static Single Assignment to the ControlFlowGraph, inserting
    /// intermediate blocks with Phi instructions as required.
    ///
    /// # Warning
    /// TODO: Handle ControlFlowGraphs which are loops
    pub fn ssa(&mut self) -> Result<()> {
        if self.entry.is_none() {
            bail!("no entry vertex set for ControlFlowGraph");
        }

        struct CfgAssigner {
            assignments: HashMap<String, u32>
        }

        impl CfgAssigner {
            pub fn new() -> CfgAssigner {
                CfgAssigner { assignments: HashMap::new() }
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
        fn ssa_block(block: &mut Block, assigner: &mut CfgAssigner) {
            let mut block_set: HashMap<String, u32> = HashMap::new();

            for operation in block.instructions_mut() {
                for variable in operation.variables_read_mut() {
                    if block_set.contains_key(variable.name()) {
                        let name = variable.name().to_string();
                        variable.set_ssa(block_set[&name]);
                    }
                }
                for variable in operation.variables_written_mut() {
                    if variable.ssa().is_none() {
                        let name = variable.name().to_string();
                        variable.set_ssa(assigner.set(name));
                    }
                    block_set.insert(
                        variable.name().to_string(),
                        variable.ssa().unwrap()
                    );
                }
            }
        }

        // Returns the ssa values for all variable assignments on block exit
        // This should be called after ssa block, and all written variables
        // should have SSA assignments.
        fn get_block_ssa_assignments(block: &Block) -> HashMap<String, Variable> {
            let mut assignments: HashMap<String, Variable> = HashMap::new();

            for operation in block.instructions() {
                for variable in operation.variables_written() {
                    // .clone().clone(), i don't want to get into it
                    let var: Variable = variable.clone().clone();
                    assignments.insert(
                        variable.name().to_string(),
                        var
                    );
                }
            }

            assignments
        }

        // Returns a vector of all variables without SSA set on exit
        fn get_block_ssa_unassigned(block: &Block) -> Vec<Variable> {
            let mut unassigned: Vec<Variable> = Vec::new();

            for operation in block.instructions() {
                for variable in operation.variables_read().iter() {
                    if variable.ssa().is_none() && !unassigned.contains(variable) {
                        unassigned.push(variable.clone().clone());
                    }
                }
            }

            unassigned
        }

        fn find_assignments(
            block: &Block,
            mut unassigned: Vec<Variable>,
            mut visited: HashSet<u64>,
            graph: &graph::Graph<Block, Edge>,
        ) -> Result<HashMap<String, HashSet<u32>>> {

            let mut found: HashMap<String, HashSet<u32>> = HashMap::new();

            // This allows us to specify whether or not to skip the first
            // block before calling this function, and use it for blocks
            // and edges
            if !visited.contains(&block.index()) {
                let assignments = get_block_ssa_assignments(block);

                let mut found_this_block = Vec::new();

                for una in unassigned.clone() {
                    if let Some(ssa_value) = assignments.get(una.name()) {
                        if !found.contains_key(una.name()) {
                            found.insert(una.name().to_owned(), HashSet::new());
                        }
                        found.get_mut(una.name())
                             .unwrap()
                             .insert(assignments[una.name()].ssa().unwrap());
                        found_this_block.push(una);
                    }
                }

                for ftb in found_this_block {
                    unassigned.iter()
                              .position(|ref n| **n == ftb)
                              .map(|e| unassigned.remove(e));
                }
                visited.insert(block.index());
            }

            let unassigned_names = unassigned.iter()
                                             .map(|v| v.name().to_owned())
                                             .collect::<Vec<String>>();

            if unassigned.len() > 0 {
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
                            found.insert(bf.0.clone(), HashSet::new());
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
        for block in self.blocks_mut() {
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
        queue.push_back(self.entry.unwrap());

        let dag = self.graph.compute_acyclic(self.entry().unwrap())?;
        let mut ssa_set: HashSet<u64> = HashSet::new();

        while queue.len() > 0 {
            let vertex_index = queue.pop_front().unwrap();

            // ensure all predecessors are set according to DAG
            let mut predecessors_set = true;
            for edge in dag.edges_in(vertex_index)? {
                let head = graph::Edge::head(edge);
                if !ssa_set.contains(&head) {
                    if !queue.contains(&head) {
                        queue.push_back(head);
                    }
                    predecessors_set = false;
                }
            }

            if !predecessors_set {
                queue.push_back(vertex_index);
                continue;
            }

            // all predecessors set
            ssa_set.insert(vertex_index);

            let (found, unassigned) = {
                let block = self.graph.vertex(vertex_index)?;

                let unassigned = get_block_ssa_unassigned(&block); 

                let mut visited = HashSet::new();
                visited.insert(block.index());

                let found = find_assignments(
                    &block,
                    unassigned.clone(),
                    visited,
                    &self.graph
                )?;
                (found, unassigned)
            };

            for una in &unassigned {
                if let Some(assignments) = found.get(una.name()) {
                    if assignments.len() == 1 {
                        let block = self.graph.vertex_mut(vertex_index)?;
                        for ref mut operation in block.instructions_mut() {
                            for ref mut variable in operation.variables_read_mut() {
                                if variable.name() == una.name()
                                   && variable.bits() == una.bits()
                                   && variable.ssa() == None {
                                    variable.set_ssa(*assignments.iter().next().unwrap());
                                }
                            }
                        }
                    }
                    else {
                        let mut dst = una.clone();
                        dst.set_ssa(assigner.get(una.name()));
                        let mut src = Vec::new();
                        for assignment in assignments.iter() {
                            let mut var = una.clone();
                            var.set_ssa(*assignment);
                            src.push(var);
                        }
                        self.graph
                            .vertex_mut(vertex_index)?
                            .prepend_phi(dst, src);
                    }
                }
            }

            // add all successors to the queue
            for edge in self.graph.edges_out(vertex_index)? {
                if !ssa_set.contains(&edge.tail()) && !queue.contains(&edge.tail()) {
                    queue.push_back(edge.tail());
                }
            }
        }

        // Every block should now have an ssa assignment in it for all
        // variable writes. We go back and make sure all reads are good to go.
        for mut block in self.blocks_mut() {
            ssa_block(block, &mut assigner);
        }
        
        let edges = { 
            self.graph
                .edges()
                .iter()
                .map(|e| (*e).clone()).collect::<Vec<Edge>>()
        };

        for edge in edges {
            if edge.condition().is_none() {
                continue;
            }

            let unassigned: Vec<Variable> = edge.condition()
                                                .clone()
                                                .unwrap()
                                                .collect_variables()
                                                .iter()
                                                .map(|v| (*v).clone())
                                                .collect();

            let found = find_assignments(
                self.graph.vertex(edge.head())?,
                unassigned,
                HashSet::new(),
                &self.graph
            )?;


            let block_index = edge.head();

            // Assign SSA to edges
            let mut phis_to_add: Vec<(u64, Variable, Vec<Variable>)> = Vec::new();

            {
                let mut edge = self.graph.edge_mut(edge.head(), edge.tail())?;

                if let &mut Some(ref mut condition) = edge.condition_mut() {
                    for variable in condition.collect_variables_mut() {
                        if let Some(assignments) = found.get(variable.name()) {
                            if assignments.len() == 1 {
                                variable.set_ssa(*assignments.iter().next().unwrap());
                                continue;
                            }
                            let mut dst = variable.clone();
                            dst.set_ssa(assigner.get(variable.name()));
                            variable.set_ssa(dst.ssa().unwrap());
                            let mut src = Vec::new();
                            for assignment in assignments.iter() {
                                let mut var = variable.clone();
                                var.set_ssa(*assignment);
                                src.push(var);
                            }
                            phis_to_add.push((block_index, dst, src));
                        }
                    }
                }
            }
            
            for phi_to_add in phis_to_add {
                self.graph
                    .vertex_mut(phi_to_add.0)?
                    .phi(phi_to_add.1, phi_to_add.2);
            }
        }

        Ok(())
    }

}


impl fmt::Display for ControlFlowGraph {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for block in self.blocks() {
            let r = writeln!(f, "{}", block);
            if r.is_err() {
                return r;
            }
        }
        Ok(())
    }
}