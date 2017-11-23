//! Definition Use Analysis

use analysis::{LocationSet, reaching_definitions};
use error::*;
use il;
use std::collections::HashMap;


#[allow(dead_code)]
/// Compute definition use chains for the given function.
pub fn def_use<'r>(function: &'r il::Function)
-> Result<HashMap<il::RefProgramLocation<'r>, LocationSet<'r>>> {
    let rd = reaching_definitions::reaching_definitions(function)?;

    let mut du: HashMap<il::RefProgramLocation<'r>, LocationSet<'r>> = HashMap::new();

    for (location, _) in &rd {
        du.entry(location.clone()).or_insert(LocationSet::new());
        match *location.function_location() {
            il::RefFunctionLocation::Instruction(_, ref instruction) => {
                for scalar_read in instruction.operation().scalars_read() {
                    for rd in rd[&location].locations() {
                        if rd.instruction()
                             .unwrap()
                             .operation()
                             .scalar_written()
                             .unwrap() == scalar_read {
                            du.entry(rd.clone()).or_insert(LocationSet::new()).insert(location.clone());
                        }
                    }
                }
            },
            il::RefFunctionLocation::Edge(ref edge) => {
                if let Some(ref condition) = *edge.condition() {
                    for scalar_read in condition.scalars() {
                        for rd in rd[&location].locations() {
                            if rd.instruction()
                                 .unwrap()
                                 .operation()
                                 .scalar_written()
                                 .unwrap() == scalar_read {
                                du.entry(rd.clone()).or_insert(LocationSet::new()).insert(location.clone());
                            }
                        }
                    }
                }
            },
            il::RefFunctionLocation::EmptyBlock(_) => {}
        }
    }

    Ok(du)
}



#[test]
fn use_def_test() {
    /*
    a = in
    b = 4
    if a < 10 {
        c = a
        [0xdeadbeef] = c
    }
    else {
        c = b
    }
    b = c
    c = [0xdeadbeef]
    */
    let mut control_flow_graph = il::ControlFlowGraph::new();

    let head_index = {
        let block = control_flow_graph.new_block().unwrap();

        block.assign(il::scalar("a", 32), il::expr_scalar("in", 32));
        block.assign(il::scalar("b", 32), il::expr_const(4, 32));

        block.index()
    };

    let gt_index = {
        let block = control_flow_graph.new_block().unwrap();

        block.assign(il::scalar("c", 32), il::expr_scalar("b", 32));

        block.index()
    };

    let lt_index = {
        let block = control_flow_graph.new_block().unwrap();

        block.assign(il::scalar("c", 32), il::expr_scalar("a", 32));
        block.store(il::expr_const(0xdeadbeef, 32), il::expr_scalar("c", 32));

        block.index()
    };

    let tail_index = {
        let block = control_flow_graph.new_block().unwrap();

        block.assign(il::scalar("b", 32), il::expr_scalar("c", 32));
        block.load(il::scalar("c", 32), il::expr_const(0xdeadbeef, 32));

        block.index()
    };

    let condition = il::Expression::cmpltu(
        il::expr_scalar("a", 32),
        il::expr_const(10, 32)
    ).unwrap();

    control_flow_graph.conditional_edge(head_index, lt_index, condition.clone()).unwrap();
    control_flow_graph.conditional_edge(head_index, gt_index, 
        il::Expression::cmpeq(condition, il::expr_const(0, 1)).unwrap()
    ).unwrap();

    control_flow_graph.unconditional_edge(lt_index, tail_index).unwrap();
    control_flow_graph.unconditional_edge(gt_index, tail_index).unwrap();

    control_flow_graph.set_entry(head_index).unwrap();

    let function = il::Function::new(0, control_flow_graph);

    let du = def_use(&function).unwrap();

    // println!("");
    // for d in du.iter() {
    //     println!("{}", d.0);
    //     for u in d.1 {
    //         println!("  {}", u);
    //     }
    // }

    let block = function.control_flow_graph().block(0).unwrap();
    assert!(du[&il::RefProgramLocation::new(
        &function,
        il::RefFunctionLocation::Instruction(
            block,
            block.instruction(0).unwrap()
        )
    )].len() == 3);

    let block = function.control_flow_graph().block(0).unwrap();
    assert!(du[&il::RefProgramLocation::new(
        &function,
        il::RefFunctionLocation::Instruction(
            block,
            block.instruction(1).unwrap()
        )
    )].len() == 1);

    let block = function.control_flow_graph().block(1).unwrap();
    assert!(du[&il::RefProgramLocation::new(
        &function,
        il::RefFunctionLocation::Instruction(
            block,
            block.instruction(0).unwrap()
        )
    )].len() == 1);

    let block = function.control_flow_graph().block(0).unwrap();
    assert!(du[&il::RefProgramLocation::new(
        &function,
        il::RefFunctionLocation::Instruction(
            block,
            block.instruction(1).unwrap()
        )
    )].contains(&il::RefProgramLocation::new(
        &function,
        il::RefFunctionLocation::Instruction(
            function.control_flow_graph().block(1).unwrap(),
            function.control_flow_graph().block(1).unwrap().instruction(0).unwrap()
        )
    )));
}