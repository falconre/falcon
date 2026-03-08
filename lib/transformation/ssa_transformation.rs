//! Static Single Assignment (SSA) Transformation

use crate::graph::*;
use crate::il;
use crate::Error;
use std::collections::{HashMap, HashSet, VecDeque};

/// Transform the IL function into SSA form.
pub fn ssa_transformation(function: &il::Function) -> Result<il::Function, Error> {
    let mut ssa_function = function.clone();
    insert_phi_nodes(&mut ssa_function)?;
    rename_scalars(&mut ssa_function)?;
    Ok(ssa_function)
}

/// Inserts phi nodes where necessary.
///
/// Implements the algorithm for constructing Semi-Pruned SSA form,
/// see Algorithm 3.1 in "SSA-based Compiler Design" book for more details.
fn insert_phi_nodes(function: &mut il::Function) -> Result<(), Error> {
    let cfg = function.control_flow_graph();
    let entry = cfg.entry().ok_or("CFG entry must be set")?;

    let dominance_frontiers = cfg.graph().compute_dominance_frontiers(entry)?;
    let non_local_scalars = compute_non_local_scalars(cfg);

    for (scalar, defs) in scalars_mutated_in_blocks(cfg) {
        if !non_local_scalars.contains(&scalar) {
            continue; // ignore local scalars
        }

        let mut phi_insertions: HashSet<usize> = HashSet::new();
        let mut queue: VecDeque<usize> = defs.iter().cloned().collect();
        while let Some(block_index) = queue.pop_front() {
            for df_index in &dominance_frontiers[&block_index] {
                if phi_insertions.contains(df_index) {
                    continue;
                }

                let phi_node = {
                    let mut phi_node = il::PhiNode::new(scalar.clone());
                    let cfg = function.control_flow_graph();
                    for predecessor in cfg.predecessor_indices(*df_index)? {
                        phi_node.add_incoming(scalar.clone(), predecessor);
                    }
                    if *df_index == entry {
                        phi_node.set_entry_scalar(scalar.clone());
                    }
                    phi_node
                };

                let cfg = function.control_flow_graph_mut();
                let df_block = cfg.block_mut(*df_index)?;
                df_block.add_phi_node(phi_node);

                phi_insertions.insert(*df_index);

                if !defs.contains(df_index) {
                    queue.push_back(*df_index);
                }
            }
        }
    }

    Ok(())
}

/// Get the set of scalars which are mutated in the given block.
fn scalars_mutated_in_block(block: &il::Block) -> HashSet<&il::Scalar> {
    block
        .instructions()
        .iter()
        .flat_map(|inst| inst.scalars_written().unwrap_or_default())
        .collect()
}

/// Get a mapping from scalars to a set of blocks (indices) in which they are mutated.
fn scalars_mutated_in_blocks(cfg: &il::ControlFlowGraph) -> HashMap<il::Scalar, HashSet<usize>> {
    let mut mutated_in = HashMap::new();

    for block in cfg.blocks() {
        for scalar in scalars_mutated_in_block(block) {
            if !mutated_in.contains_key(scalar) {
                mutated_in.insert(scalar.clone(), HashSet::new());
            }
            mutated_in.get_mut(scalar).unwrap().insert(block.index());
        }
    }

    mutated_in
}

// Computes the set of scalars that are live on entry of at least one block.
// Such scalars are denoted as "non locals" in the algorithm for Semi-Pruned SSA.
fn compute_non_local_scalars(cfg: &il::ControlFlowGraph) -> HashSet<il::Scalar> {
    let mut non_locals = HashSet::new();

    for block in cfg.blocks() {
        let mut killed = HashSet::new();

        block.instructions().iter().for_each(|inst| {
            inst.scalars_read()
                .unwrap_or_default()
                .into_iter()
                .filter(|scalar| !killed.contains(scalar))
                .for_each(|scalar| {
                    non_locals.insert(scalar.clone());
                });

            inst.scalars_written()
                .unwrap_or_default()
                .into_iter()
                .for_each(|scalar| {
                    killed.insert(scalar);
                });
        });
    }

    non_locals
}

fn rename_scalars(function: &mut il::Function) -> Result<(), Error> {
    let mut versioning = ScalarVersioning::new();
    function.rename_scalars(&mut versioning)
}

struct ScalarVersioning {
    counter: HashMap<String, usize>,
    scoped_versions: Vec<HashMap<String, usize>>,
}

impl ScalarVersioning {
    pub fn new() -> Self {
        Self {
            counter: HashMap::new(),
            scoped_versions: Vec::new(),
        }
    }

    pub fn start_new_scope(&mut self) {
        let scope = match self.scoped_versions.last() {
            Some(parent_scope) => parent_scope.clone(),
            None => HashMap::new(),
        };
        self.scoped_versions.push(scope);
    }

    pub fn end_scope(&mut self) {
        self.scoped_versions.pop();
    }

    fn get_version(&mut self, scalar: &il::Scalar) -> Option<usize> {
        self.scoped_versions
            .last()
            .and_then(|versions| versions.get(scalar.name()))
            .copied()
    }

    fn new_version(&mut self, scalar: &il::Scalar) -> usize {
        let count = self.counter.entry(scalar.name().to_string()).or_insert(1);
        let version = *count;
        *count += 1;

        let versions = self.scoped_versions.last_mut().unwrap();
        versions.insert(scalar.name().to_string(), version);

        version
    }
}

trait SsaRename {
    fn rename_scalars(&mut self, versioning: &mut ScalarVersioning) -> Result<(), Error>;
}

impl SsaRename for il::Expression {
    fn rename_scalars(&mut self, versioning: &mut ScalarVersioning) -> Result<(), Error> {
        for scalar in self.scalars_mut() {
            scalar.set_ssa(versioning.get_version(scalar));
        }

        Ok(())
    }
}

impl SsaRename for il::Instruction {
    fn rename_scalars(&mut self, versioning: &mut ScalarVersioning) -> Result<(), Error> {
        // rename all read scalars
        if let Some(mut scalars_read) = self.scalars_read_mut() {
            for scalar in scalars_read.iter_mut() {
                scalar.set_ssa(versioning.get_version(scalar));
            }
        }

        // introduce new SSA names for written scalars
        if let Some(mut scalar_written) = self.scalar_written_mut() {
            for scalar in scalar_written.iter_mut() {
                scalar.set_ssa(Some(versioning.new_version(scalar)));
            }
        }

        Ok(())
    }
}

impl SsaRename for il::Block {
    fn rename_scalars(&mut self, versioning: &mut ScalarVersioning) -> Result<(), Error> {
        // introduce new SSA names for phi node outputs
        for phi_node in self.phi_nodes_mut() {
            let scalar = phi_node.out_mut();
            scalar.set_ssa(Some(versioning.new_version(scalar)));
        }

        for inst in self.instructions_mut() {
            inst.rename_scalars(versioning)?;
        }

        Ok(())
    }
}

impl SsaRename for il::ControlFlowGraph {
    fn rename_scalars(&mut self, versioning: &mut ScalarVersioning) -> Result<(), Error> {
        let entry = self.entry().ok_or("CFG entry must be set")?;

        type DominatorTree = Graph<NullVertex, NullEdge>;
        let dominator_tree = self.graph().compute_dominator_tree(entry)?;

        fn dominator_tree_dfs_pre_order_traverse(
            cfg: &mut il::ControlFlowGraph,
            dominator_tree: &DominatorTree,
            node: usize,
            versioning: &mut ScalarVersioning,
        ) -> Result<(), Error> {
            versioning.start_new_scope();

            let block = cfg.block_mut(node)?;
            block.rename_scalars(versioning)?;

            let immediate_successors = cfg.successor_indices(node)?;
            for successor_index in immediate_successors {
                // rename scalars in conditions of all outgoing edges
                let edge = cfg.edge_mut(node, successor_index)?;
                if let Some(condition) = edge.condition_mut() {
                    condition.rename_scalars(versioning)?
                }

                // rename all scalars of successor phi nodes which originate from this block
                let successor_block = cfg.block_mut(successor_index)?;
                for phi_node in successor_block.phi_nodes_mut() {
                    if let Some(incoming_scalar) = phi_node.incoming_scalar_mut(node) {
                        incoming_scalar.set_ssa(versioning.get_version(incoming_scalar));
                    }
                }
            }

            for successor in dominator_tree.successors(node)? {
                dominator_tree_dfs_pre_order_traverse(
                    cfg,
                    dominator_tree,
                    successor.index(),
                    versioning,
                )?;
            }

            versioning.end_scope();

            Ok(())
        }

        dominator_tree_dfs_pre_order_traverse(self, &dominator_tree, entry, versioning)
    }
}

impl SsaRename for il::Function {
    fn rename_scalars(&mut self, versioning: &mut ScalarVersioning) -> Result<(), Error> {
        self.control_flow_graph_mut().rename_scalars(versioning)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    pub fn scalar_ssa<S>(name: S, bits: usize, ssa: usize) -> il::Scalar
    where
        S: Into<String>,
    {
        let mut scalar = il::Scalar::new(name, bits);
        scalar.set_ssa(Some(ssa));
        scalar
    }

    pub fn expr_scalar_ssa<S>(name: S, bits: usize, ssa: usize) -> il::Expression
    where
        S: Into<String>,
    {
        il::Expression::scalar(scalar_ssa(name, bits, ssa))
    }

    #[test]
    fn test_scalars_mutated_in_block() {
        let block = {
            let mut block = il::Block::new(0);
            block.assign(il::scalar("x", 64), il::expr_const(1, 64));
            block.load(il::scalar("y", 64), il::expr_scalar("z", 64));
            block.assign(il::scalar("x", 64), il::expr_scalar("y", 64));
            block.nop();
            block
        };

        assert_eq!(
            scalars_mutated_in_block(&block),
            vec![&il::scalar("x", 64), &il::scalar("y", 64)]
                .into_iter()
                .collect()
        );
    }

    #[test]
    fn test_scalars_mutated_in_blocks() {
        let cfg = {
            let mut cfg = il::ControlFlowGraph::new();

            let block0 = cfg.new_block().unwrap();
            block0.assign(il::scalar("x", 64), il::expr_const(1, 64));

            let block1 = cfg.new_block().unwrap();
            block1.load(il::scalar("y", 64), il::expr_scalar("z", 64));

            let block2 = cfg.new_block().unwrap();
            block2.assign(il::scalar("x", 64), il::expr_scalar("y", 64));

            cfg
        };

        let mutated_in_blocks = scalars_mutated_in_blocks(&cfg);

        assert_eq!(
            mutated_in_blocks[&il::scalar("x", 64)],
            vec![0, 2].into_iter().collect()
        );
        assert_eq!(
            mutated_in_blocks[&il::scalar("y", 64)],
            vec![1].into_iter().collect()
        );
    }

    #[test]
    fn test_compute_non_local_scalars() {
        let cfg = {
            let mut cfg = il::ControlFlowGraph::new();

            let block0 = cfg.new_block().unwrap();
            block0.assign(il::scalar("x", 64), il::expr_const(1, 64));

            let block1 = cfg.new_block().unwrap();
            block1.assign(il::scalar("tmp", 64), il::expr_const(1, 64));
            block1.assign(il::scalar("x", 64), il::expr_scalar("tmp", 64));

            let block2 = cfg.new_block().unwrap();
            block2.load(il::scalar("y", 64), il::expr_scalar("x", 64));

            cfg
        };

        assert_eq!(
            compute_non_local_scalars(&cfg),
            vec![il::scalar("x", 64)].into_iter().collect()
        );
    }

    #[test]
    fn test_renaming_of_expression() {
        // Given: x + y * x
        let mut expression = il::Expression::add(
            il::expr_scalar("x", 64),
            il::Expression::mul(il::expr_scalar("y", 64), il::expr_scalar("x", 64)).unwrap(),
        )
        .unwrap();

        let mut versioning = ScalarVersioning::new();
        versioning.start_new_scope();
        versioning.new_version(&il::scalar("x", 64));
        versioning.new_version(&il::scalar("y", 64));
        expression.rename_scalars(&mut versioning).unwrap();

        // Expected: x_1 + y_1 * x_1
        assert_eq!(
            expression,
            il::Expression::add(
                expr_scalar_ssa("x", 64, 1),
                il::Expression::mul(expr_scalar_ssa("y", 64, 1), expr_scalar_ssa("x", 64, 1))
                    .unwrap(),
            )
            .unwrap()
        );
    }

    #[test]
    fn test_renaming_of_nop_instruction() {
        // Given: nop
        let mut instruction = il::Instruction::nop(0);

        let mut versioning = ScalarVersioning::new();
        versioning.start_new_scope();
        instruction.rename_scalars(&mut versioning).unwrap();

        // Expected: nop
        assert_eq!(instruction, il::Instruction::nop(0));
    }

    #[test]
    fn test_renaming_of_assign_instruction() {
        // Given: x := x
        let mut instruction =
            il::Instruction::assign(0, il::scalar("x", 64), il::expr_scalar("x", 64));

        let mut versioning = ScalarVersioning::new();
        versioning.start_new_scope();
        versioning.new_version(&il::scalar("x", 64));
        instruction.rename_scalars(&mut versioning).unwrap();

        // Expected: x_2 := x_1
        assert_eq!(
            instruction,
            il::Instruction::assign(0, scalar_ssa("x", 64, 2), expr_scalar_ssa("x", 64, 1),)
        );
    }

    #[test]
    fn test_renaming_of_load_instruction() {
        // Given: x := [x]
        let mut instruction =
            il::Instruction::load(0, il::scalar("x", 64), il::expr_scalar("x", 64));

        let mut versioning = ScalarVersioning::new();
        versioning.start_new_scope();
        versioning.new_version(&il::scalar("x", 64));
        instruction.rename_scalars(&mut versioning).unwrap();

        // Expected: x_2 := [x_1]
        assert_eq!(
            instruction,
            il::Instruction::load(0, scalar_ssa("x", 64, 2), expr_scalar_ssa("x", 64, 1))
        );
    }

    #[test]
    fn test_renaming_of_store_instruction() {
        // Given: [x] := x
        let mut instruction =
            il::Instruction::store(0, il::expr_scalar("x", 64), il::expr_scalar("x", 64));

        let mut versioning = ScalarVersioning::new();
        versioning.start_new_scope();
        versioning.new_version(&il::scalar("x", 64));
        instruction.rename_scalars(&mut versioning).unwrap();

        // Expected: [x_1] := x_1
        assert_eq!(
            instruction,
            il::Instruction::store(0, expr_scalar_ssa("x", 64, 1), expr_scalar_ssa("x", 64, 1))
        );
    }

    #[test]
    fn test_renaming_of_branch_instruction() {
        // Given: brc x
        let mut instruction = il::Instruction::branch(0, il::expr_scalar("x", 64));

        let mut versioning = ScalarVersioning::new();
        versioning.start_new_scope();
        versioning.new_version(&il::scalar("x", 64));
        instruction.rename_scalars(&mut versioning).unwrap();

        // Expected: brc x_1
        assert_eq!(
            instruction,
            il::Instruction::branch(0, expr_scalar_ssa("x", 64, 1))
        );
    }

    #[test]
    fn test_renaming_of_block() {
        // Given:
        // y = phi []
        // x = y
        // y = [x]
        // x = y
        // z = x
        let mut block = il::Block::new(0);
        block.add_phi_node(il::PhiNode::new(il::scalar("y", 64)));
        block.assign(il::scalar("x", 64), il::expr_scalar("y", 64));
        block.load(il::scalar("y", 64), il::expr_scalar("x", 64));
        block.assign(il::scalar("x", 64), il::expr_scalar("y", 64));
        block.assign(il::scalar("z", 64), il::expr_scalar("x", 64));

        let mut versioning = ScalarVersioning::new();
        versioning.start_new_scope();
        block.rename_scalars(&mut versioning).unwrap();

        // Expected:
        // y_1 = phi []
        // x_1 = 1
        // y_2 = [x_1]
        // x_2 = y_2
        // z_1 = x_2
        assert_eq!(
            block.phi_node(0).unwrap(),
            &il::PhiNode::new(scalar_ssa("y", 64, 1))
        );
        assert_eq!(
            block.instruction(0).unwrap().operation(),
            &il::Operation::assign(scalar_ssa("x", 64, 1), expr_scalar_ssa("y", 64, 1))
        );
        assert_eq!(
            block.instruction(1).unwrap().operation(),
            &il::Operation::load(scalar_ssa("y", 64, 2), expr_scalar_ssa("x", 64, 1))
        );
        assert_eq!(
            block.instruction(2).unwrap().operation(),
            &il::Operation::assign(scalar_ssa("x", 64, 2), expr_scalar_ssa("y", 64, 2))
        );
        assert_eq!(
            block.instruction(3).unwrap().operation(),
            &il::Operation::assign(scalar_ssa("z", 64, 1), expr_scalar_ssa("x", 64, 2))
        );
    }

    #[test]
    fn test_renaming_of_conditional_edges() {
        // Given:
        // x = 1
        // nop   +---+
        // -----     | (x)
        // x = x <---+
        // nop   +---+
        // -----     | (x)
        // x = x <---+
        let mut cfg = il::ControlFlowGraph::new();

        let block0 = cfg.new_block().unwrap();
        block0.assign(il::scalar("x", 64), il::expr_const(1, 64));
        block0.nop();

        let block1 = cfg.new_block().unwrap();
        block1.assign(il::scalar("x", 64), il::expr_scalar("x", 64));
        block1.nop();

        let block2 = cfg.new_block().unwrap();
        block2.assign(il::scalar("x", 64), il::expr_scalar("x", 64));

        cfg.set_entry(0).unwrap();

        cfg.conditional_edge(0, 1, il::expr_scalar("x", 64))
            .unwrap();
        cfg.conditional_edge(1, 2, il::expr_scalar("x", 64))
            .unwrap();

        let mut versioning = ScalarVersioning::new();
        versioning.start_new_scope();
        cfg.rename_scalars(&mut versioning).unwrap();

        // Expected:
        // x_1 = 1
        // nop       +---+
        // ---------     | (x_1)
        // x_2 = x_1 <---+
        // nop       +---+
        // ---------     | (x_2)
        // x_3 = x_2 <---+
        let ssa_block0 = cfg.block(0).unwrap();
        assert_eq!(
            ssa_block0.instruction(0).unwrap().operation(),
            &il::Operation::assign(scalar_ssa("x", 64, 1), il::expr_const(1, 64))
        );

        let ssa_block1 = cfg.block(1).unwrap();
        assert_eq!(
            ssa_block1.instruction(0).unwrap().operation(),
            &il::Operation::assign(scalar_ssa("x", 64, 2), expr_scalar_ssa("x", 64, 1))
        );

        let ssa_block2 = cfg.block(2).unwrap();
        assert_eq!(
            ssa_block2.instruction(0).unwrap().operation(),
            &il::Operation::assign(scalar_ssa("x", 64, 3), expr_scalar_ssa("x", 64, 2))
        );

        let ssa_edge01 = cfg.edge(0, 1).unwrap();
        assert_eq!(
            ssa_edge01.condition().unwrap(),
            &expr_scalar_ssa("x", 64, 1)
        );

        let ssa_edge12 = cfg.edge(1, 2).unwrap();
        assert_eq!(
            ssa_edge12.condition().unwrap(),
            &expr_scalar_ssa("x", 64, 2)
        );
    }

    #[test]
    fn test_renaming_of_incoming_edges_in_phi_nodes() {
        // Given:
        //         block 0
        //   +---+ y = 1 +---+
        //   |               |
        //   v               v
        // block 1         block 2
        // x = 2           x = 4
        // y = 3             +
        //   |               |
        //   +-------+-------+
        //           |
        //           v
        //        block 3
        // x = phi [x, 1] [x, 2]
        // y = phi [y, 1] [y, 2]
        let mut cfg = il::ControlFlowGraph::new();

        let block0 = cfg.new_block().unwrap();
        block0.assign(il::scalar("y", 64), il::expr_const(1, 64));

        let block1 = cfg.new_block().unwrap();
        block1.assign(il::scalar("x", 64), il::expr_const(2, 64));
        block1.assign(il::scalar("y", 64), il::expr_const(3, 64));

        let block2 = cfg.new_block().unwrap();
        block2.assign(il::scalar("x", 64), il::expr_const(4, 64));

        let mut phi_node_x = il::PhiNode::new(il::scalar("x", 64));
        phi_node_x.add_incoming(il::scalar("x", 64), 1);
        phi_node_x.add_incoming(il::scalar("x", 64), 2);

        let mut phi_node_y = il::PhiNode::new(il::scalar("y", 64));
        phi_node_y.add_incoming(il::scalar("y", 64), 1);
        phi_node_y.add_incoming(il::scalar("y", 64), 2);

        let block3 = cfg.new_block().unwrap();
        block3.add_phi_node(phi_node_x);
        block3.add_phi_node(phi_node_y);

        cfg.set_entry(0).unwrap();

        cfg.unconditional_edge(0, 1).unwrap();
        cfg.unconditional_edge(0, 2).unwrap();
        cfg.unconditional_edge(1, 3).unwrap();
        cfg.unconditional_edge(2, 3).unwrap();

        let mut versioning = ScalarVersioning::new();
        versioning.start_new_scope();
        cfg.rename_scalars(&mut versioning).unwrap();

        // Expected:
        //         block 0
        //   +---+ y_1 = 1 +---+
        //   |                 |
        //   v                 v
        // block 1           block 2
        // x_1 = 2           x_2 = 4
        // y_2 = 3             +
        //   |                 |
        //   +--------+--------+
        //            |
        //            v
        //          block 3
        // x_3 = phi [x_1, 1] [x_2, 2]
        // y_3 = phi [y_2, 1] [y_1, 2]
        let ssa_block3 = cfg.block(3).unwrap();

        let ssa_phi_node_x = ssa_block3.phi_node(0).unwrap();
        assert_eq!(ssa_phi_node_x.out(), &scalar_ssa("x", 64, 3));
        assert_eq!(
            ssa_phi_node_x.incoming_scalar(1).unwrap(),
            &scalar_ssa("x", 64, 1)
        );
        assert_eq!(
            ssa_phi_node_x.incoming_scalar(2).unwrap(),
            &scalar_ssa("x", 64, 2)
        );

        let ssa_phi_node_y = ssa_block3.phi_node(1).unwrap();
        assert_eq!(ssa_phi_node_y.out(), &scalar_ssa("y", 64, 3));
        assert_eq!(
            ssa_phi_node_y.incoming_scalar(1).unwrap(),
            &scalar_ssa("y", 64, 2)
        );
        assert_eq!(
            ssa_phi_node_y.incoming_scalar(2).unwrap(),
            &scalar_ssa("y", 64, 1)
        );
    }

    #[test]
    fn test_insert_phi_nodes() {
        // Given:
        //             |
        //             v
        // +-------> block 0
        // |           |
        // |       +---+---+
        // |       |       |
        // |       v       v
        // |   block 1  block 2 +---+
        // |    x = 0      |        |
        // |       |       |        |
        // |       +---+---+        |
        // |           |            |
        // |           v            |
        // +------+ block 3         |
        //             |            |
        //             v            |
        //          block 4 <-------+
        //           y = x
        let mut function = {
            let mut cfg = il::ControlFlowGraph::new();

            // block0
            {
                cfg.new_block().unwrap();
            }
            // block1
            {
                let block = cfg.new_block().unwrap();
                block.assign(il::scalar("x", 64), il::expr_const(0, 64));
            }
            // block2
            {
                cfg.new_block().unwrap();
            }
            // block3
            {
                cfg.new_block().unwrap();
            }
            // block4
            {
                let block = cfg.new_block().unwrap();
                block.assign(il::scalar("y", 64), il::expr_scalar("x", 64));
            }

            cfg.unconditional_edge(0, 1).unwrap();
            cfg.unconditional_edge(0, 2).unwrap();
            cfg.unconditional_edge(1, 3).unwrap();
            cfg.unconditional_edge(2, 3).unwrap();
            cfg.unconditional_edge(2, 4).unwrap();
            cfg.unconditional_edge(3, 0).unwrap();
            cfg.unconditional_edge(3, 4).unwrap();

            cfg.set_entry(0).unwrap();

            il::Function::new(0, cfg)
        };

        insert_phi_nodes(&mut function).unwrap();

        // Expected:
        //             |
        //             v
        // +-------> block 0
        // | x = phi [x, 3] [x, entry]
        // |           |
        // |       +---+---+
        // |       |       |
        // |       v       v
        // |   block 1  block 2 +---+
        // |       |       |        |
        // |       +---+---+        |
        // |           |            |
        // |           v            |
        // +------+ block 3         |
        //  x = phi [x, 1] [x, 2]   |
        //             |            |
        //             v            |
        //          block 4 <-------+
        //  x = phi [x, 3] [x, 2]
        let block0 = function.block(0).unwrap();
        let block1 = function.block(1).unwrap();
        let block2 = function.block(2).unwrap();
        let block3 = function.block(3).unwrap();
        let block4 = function.block(4).unwrap();

        assert_eq!(block0.phi_nodes().len(), 1);
        assert_eq!(block1.phi_nodes().len(), 0);
        assert_eq!(block2.phi_nodes().len(), 0);
        assert_eq!(block3.phi_nodes().len(), 1);
        assert_eq!(block4.phi_nodes().len(), 1);

        let phi_node_block0 = block0.phi_node(0).unwrap();
        assert_eq!(phi_node_block0.out(), &il::scalar("x", 64));
        assert_eq!(
            phi_node_block0.incoming_scalar(3).unwrap(),
            &il::scalar("x", 64)
        );
        assert_eq!(
            phi_node_block0.entry_scalar().unwrap(),
            &il::scalar("x", 64)
        );

        let phi_node_block3 = block3.phi_node(0).unwrap();
        assert_eq!(phi_node_block3.out(), &il::scalar("x", 64));
        assert_eq!(
            phi_node_block3.incoming_scalar(1).unwrap(),
            &il::scalar("x", 64)
        );
        assert_eq!(
            phi_node_block3.incoming_scalar(2).unwrap(),
            &il::scalar("x", 64)
        );

        let phi_node_block4 = block4.phi_node(0).unwrap();
        assert_eq!(phi_node_block4.out(), &il::scalar("x", 64));
        assert_eq!(
            phi_node_block4.incoming_scalar(3).unwrap(),
            &il::scalar("x", 64)
        );
        assert_eq!(
            phi_node_block4.incoming_scalar(2).unwrap(),
            &il::scalar("x", 64)
        );
    }

    #[test]
    fn test_complete_ssa_transformation() {
        // Given:
        //             |
        //             v
        // +-------> block 0
        // |           |
        // |       +---+---+
        // |       |       |
        // |       v       v
        // |   block 1  block 2 +---+
        // |    x = 0   tmp = x     |
        // |       |    x = tmp     |
        // |       |       |        |
        // |       +---+---+        |
        // |           |            |
        // |           v            |
        // +------+ block 3         |
        //          x = x + x       |
        //             |            |
        //             v            |
        //          block 4 <-------+
        //           res = x
        let function = {
            let mut cfg = il::ControlFlowGraph::new();

            // block0
            {
                cfg.new_block().unwrap();
            }
            // block1
            {
                let block = cfg.new_block().unwrap();
                block.assign(il::scalar("x", 64), il::expr_const(0, 64));
            }
            // block2
            {
                let block = cfg.new_block().unwrap();
                block.assign(il::scalar("tmp", 64), il::expr_scalar("x", 64));
                block.assign(il::scalar("x", 64), il::expr_scalar("tmp", 64));
            }
            // block3
            {
                let block = cfg.new_block().unwrap();
                block.assign(
                    il::scalar("x", 64),
                    il::Expression::add(il::expr_scalar("x", 64), il::expr_scalar("x", 64))
                        .unwrap(),
                );
            }
            // block4
            {
                let block = cfg.new_block().unwrap();
                block.assign(il::scalar("res", 64), il::expr_scalar("x", 64));
            }

            cfg.unconditional_edge(0, 1).unwrap();
            cfg.unconditional_edge(0, 2).unwrap();
            cfg.unconditional_edge(1, 3).unwrap();
            cfg.unconditional_edge(2, 3).unwrap();
            cfg.unconditional_edge(2, 4).unwrap();
            cfg.unconditional_edge(3, 0).unwrap();
            cfg.unconditional_edge(3, 4).unwrap();

            cfg.set_entry(0).unwrap();

            il::Function::new(0, cfg)
        };

        let ssa_function = ssa_transformation(&function).unwrap();

        // Expected:
        //             |
        //             v
        // +-------> block 0
        // | x1 = phi [x5, 3] [x, entry]
        // |           |
        // |       +---+---+
        // |       |       |
        // |       v       v
        // |   block 1  block 2 +---+
        // |   x2 = 0   tmp1 = x1   |
        // |       |    x3 = tmp1   |
        // |       |       |        |
        // |       +---+---+        |
        // |           |            |
        // |           v            |
        // +------+ block 3         |
        // x4 = phi [x2, 1] [x3, 2] |
        //        x5 = x4 + x4      |
        //             |            |
        //             v            |
        //          block 4 <-------+
        //  x6 = phi [x5, 3] [x3, 2]
        //         res1 = x6
        let expected_function = {
            let mut cfg = il::ControlFlowGraph::new();

            // block0
            {
                let block = cfg.new_block().unwrap();
                block.add_phi_node({
                    let mut phi_node = il::PhiNode::new(scalar_ssa("x", 64, 1));
                    phi_node.add_incoming(scalar_ssa("x", 64, 5), 3);
                    phi_node.set_entry_scalar(il::scalar("x", 64));
                    phi_node
                });
            }
            // block1
            {
                let block = cfg.new_block().unwrap();
                block.assign(scalar_ssa("x", 64, 2), il::expr_const(0, 64));
            }
            // block2
            {
                let block = cfg.new_block().unwrap();
                block.assign(scalar_ssa("tmp", 64, 1), expr_scalar_ssa("x", 64, 1));
                block.assign(scalar_ssa("x", 64, 3), expr_scalar_ssa("tmp", 64, 1));
            }
            // block3
            {
                let block = cfg.new_block().unwrap();
                block.assign(
                    scalar_ssa("x", 64, 5),
                    il::Expression::add(expr_scalar_ssa("x", 64, 4), expr_scalar_ssa("x", 64, 4))
                        .unwrap(),
                );
                block.add_phi_node({
                    let mut phi_node = il::PhiNode::new(scalar_ssa("x", 64, 4));
                    phi_node.add_incoming(scalar_ssa("x", 64, 2), 1);
                    phi_node.add_incoming(scalar_ssa("x", 64, 3), 2);
                    phi_node
                });
            }
            // block4
            {
                let block = cfg.new_block().unwrap();
                block.assign(scalar_ssa("res", 64, 1), expr_scalar_ssa("x", 64, 6));
                block.add_phi_node({
                    let mut phi_node = il::PhiNode::new(scalar_ssa("x", 64, 6));
                    phi_node.add_incoming(scalar_ssa("x", 64, 5), 3);
                    phi_node.add_incoming(scalar_ssa("x", 64, 3), 2);
                    phi_node
                });
            }

            cfg.unconditional_edge(0, 1).unwrap();
            cfg.unconditional_edge(0, 2).unwrap();
            cfg.unconditional_edge(1, 3).unwrap();
            cfg.unconditional_edge(2, 3).unwrap();
            cfg.unconditional_edge(2, 4).unwrap();
            cfg.unconditional_edge(3, 0).unwrap();
            cfg.unconditional_edge(3, 4).unwrap();

            cfg.set_entry(0).unwrap();

            il::Function::new(0, cfg)
        };

        assert_eq!(ssa_function, expected_function);
    }
}
