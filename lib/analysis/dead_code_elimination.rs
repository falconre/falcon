//! An optimization to eliminate dead code from the graph.

use analysis::Analysis;
use analysis::analysis_location::*;
use error::*;
use il;
use std::collections::{BTreeSet, VecDeque};


pub fn dead_code_elimination(analysis: &Analysis) -> Result<il::ControlFlowGraph> {
    let mut cfg = analysis.control_flow_graph().clone();

    // We need to find the essential variable assignments. We will define the
    // following as essential:
    // * All assignments which are live at the point of a brc instruction.
    // * All assignments which store data (affect state we can't monitor)
    // * All assignments which reach out of the end of all blocks which do not
    //   have successors (terminating blocks).
    // * All variable in edge conditions
    let mut work_queue: VecDeque<AnalysisLocation> = VecDeque::new();

    // We are going to fill our marked set with all analysis_locations,
    // and remove the ones we want to keep.
    let mut marked: BTreeSet<AnalysisLocation> = BTreeSet::new();

    for block in cfg.blocks() {
        for instruction in block.instructions() {
            let il = InstructionLocation::new(
                block.index(),
                instruction.index()
            );
            if instruction.is_brc() || instruction.is_store() {
                work_queue.push_back(il.clone().into());
            }
            marked.insert(il.into());
        }

        if cfg.graph().edges_out(block.index()).unwrap().is_empty() {
            if block.instructions().is_empty() {
                let al = AnalysisLocation::empty_block(block.index());
                for al in analysis.reaching_definitions()[&al].out() {
                    work_queue.push_back(al.clone());
                }
            }
            else {
                let al = AnalysisLocation::instruction(
                    block.index(),
                    block.instructions().last().unwrap().index()
                );
                for al in analysis.reaching_definitions()[&al].out() {
                    work_queue.push_back(al.clone());
                }
            }
        }
    }

    for edge in cfg.edges() {
        if edge.condition().is_some() {
            let al = AnalysisLocation::edge(edge.head(), edge.tail());
            work_queue.push_back(al.clone());
            marked.insert(al.clone());
        }
    }

    while !work_queue.is_empty() {
        let al = work_queue.pop_front().unwrap();

        if !marked.contains(&al) {
            continue;
        }

        marked.remove(&al);

        for ud in &analysis.use_def()[&al.clone().into()] {
            match *ud {
                AnalysisLocation::Edge(ref el) => {
                    work_queue.push_back(el.clone().into());
                },
                AnalysisLocation::Instruction(ref il) => {
                    work_queue.push_back(il.clone().into());
                }
                // empty blocks don't define anything
                AnalysisLocation::EmptyBlock(_) => {}
            }
        }
    }

    for kill in &marked {
        match *kill {
            // We shouldn't be removing edges or empty blocks
            AnalysisLocation::EmptyBlock(_) |
            AnalysisLocation::Edge(_) => continue,
            AnalysisLocation::Instruction(ref il) => {
                let mut block = cfg.block_mut(il.block_index())
                                   .ok_or("Could not find block")?;
                block.remove_instruction(il.instruction_index())?;
            }
        }
    }

    Ok(cfg)
}