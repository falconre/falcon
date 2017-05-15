//! Simplifies the IL
//!
//! ## Assignment Propagation
//! Given two assignments:
//! ```
//! V0 = EXPR
//! V1 = V0
//! ```
//! Where `V1 = V0` is the only use of V0, we replace `V1 = V0` with
//! `V1 = EXPR`. This pass should be followed with dead code eliminiation.
//! This cleans up temporary variables nicely.

use analysis::Analysis;
use analysis::analysis_location::*;
use error::*;
use il;
use std::collections::{BTreeMap};





fn assignment_propagation(analysis: &Analysis) -> Result<il::ControlFlowGraph> {
    let mut cfg = analysis.control_flow_graph().clone();

    let mut single_assignments: BTreeMap<AnalysisLocation, AnalysisLocation> = BTreeMap::new();

    let def_use = analysis.def_use();
    let use_def = analysis.use_def();

    // Find all defs that are used only once
    for du in def_use {
        let al = du.0.clone();
        let uses = du.1;

        if let AnalysisLocation::Instruction(ref il) = al {
            let instruction = il.find(analysis.control_flow_graph())?;
            if instruction.is_phi() {
                continue;
            }
        }

        if uses.len() == 1 {
            let use_ = uses.iter().next().unwrap();
            if let AnalysisLocation::Instruction(ref il) = *use_ {
                let use_ins = il.find(&analysis.control_flow_graph())?;
                if !use_ins.is_assign() {
                    continue;
                }
            }
            if let Some(defs) = use_def.get(use_) {
                if defs.len() == 1 {
                    //trace!("{} has one use and is the only def for that use", al);
                    single_assignments.insert(use_.clone(), al.clone());
                }
            }
        }
    }

    /*
    V1 = V0
    V2 = V1
    V3 = V2
    V4 = V0
    v5 = V4 + V3
    */

    // For all assignments that are used only once
    for def in &single_assignments {
        let target_al = def.0.clone();
        let mut source_al = def.1.clone();

        while single_assignments.contains_key(&source_al) {
            trace!("source_al = {}", source_al);
            source_al = single_assignments[&source_al].clone();
        }

        // Find the target InstructionLocation
        let target_il = match target_al {
            AnalysisLocation::Edge(_) |
            AnalysisLocation::EmptyBlock(_) => {
                bail!("simplification found assignment in Edge/EmptyBlock")
            },
            AnalysisLocation::Instruction(il) => il
        };

        // Find the source InstructionLocation
        let source_il = match source_al {
            AnalysisLocation::Edge(_) |
            AnalysisLocation::EmptyBlock(_) => {
                bail!("simplification found assignment in Edge/EmptyBlock")
            },
            AnalysisLocation::Instruction(il) => il
        };

        let target_ins = target_il.find(analysis.control_flow_graph())?;
        let source_ins = source_il.find(analysis.control_flow_graph())?;

        // Find the variable we are assigning to
        let target_variable = match *target_ins.operation() {
            il::Operation::Assign{ref dst, src: _} => dst.clone(),
            _ => bail!("Invalid target instruction in simplification: {}",
                target_il.find(analysis.control_flow_graph())?)
        };

        // Find the expression we are assigning from
        let operation = match *source_ins.operation() {
            il::Operation::Assign{dst: _, ref src} => 
                il::Operation::assign(target_variable, src.clone()),
            il::Operation::Load{dst: _, ref address} =>
                il::Operation::load(target_variable, address.clone()),
            _ => bail!("Invalid source instruction in simplification")
        };

        //trace!("Replacing {} with {}", target_il, operation);
        // Replace the target operation
        *target_il.find_mut(&mut cfg)?.operation_mut() = operation;
    }

    Ok(cfg)
}


pub fn simplification(analysis: &Analysis) -> Result<il::ControlFlowGraph> {
    assignment_propagation(analysis)
}