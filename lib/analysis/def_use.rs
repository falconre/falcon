//! Definition Use Analysis

use crate::analysis::{reaching_definitions, LocationSet};
use crate::il;
use crate::Error;
use std::collections::HashMap;

#[allow(dead_code)]
/// Compute definition use chains for the given function.
pub fn def_use(
    function: &il::Function,
) -> Result<HashMap<il::ProgramLocation, LocationSet>, Error> {
    let rd = reaching_definitions::reaching_definitions(function)?;

    let mut du: HashMap<il::ProgramLocation, LocationSet> = HashMap::new();

    for location in rd.keys() {
        du.entry(location.clone()).or_insert_with(LocationSet::new);
        match location.function_location().apply(function).unwrap() {
            il::RefFunctionLocation::Instruction(_, instruction) => instruction
                .operation()
                .scalars_read()
                .into_iter()
                .for_each(|scalar_read| {
                    rd[location].locations().iter().for_each(|rd| {
                        rd.function_location()
                            .apply(function)
                            .unwrap()
                            .instruction()
                            .unwrap()
                            .operation()
                            .scalars_written()
                            .into_iter()
                            .for_each(|scalar_written| {
                                if scalar_written == scalar_read {
                                    du.entry(rd.clone())
                                        .or_insert_with(LocationSet::new)
                                        .insert(location.clone());
                                }
                            })
                    })
                }),
            il::RefFunctionLocation::Edge(edge) => {
                if let Some(condition) = edge.condition() {
                    condition.scalars().into_iter().for_each(|scalar_read| {
                        rd[location].locations().iter().for_each(|rd| {
                            if let Some(scalars_written) = rd
                                .function_location()
                                .apply(function)
                                .unwrap()
                                .instruction()
                                .unwrap()
                                .operation()
                                .scalars_written()
                            {
                                scalars_written.into_iter().for_each(|scalar_written| {
                                    if scalar_written == scalar_read {
                                        du.entry(rd.clone())
                                            .or_insert_with(LocationSet::new)
                                            .insert(location.clone());
                                    }
                                })
                            }
                        })
                    })
                }
            }
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

    let condition =
        il::Expression::cmpltu(il::expr_scalar("a", 32), il::expr_const(10, 32)).unwrap();

    control_flow_graph
        .conditional_edge(head_index, lt_index, condition.clone())
        .unwrap();
    control_flow_graph
        .conditional_edge(
            head_index,
            gt_index,
            il::Expression::cmpeq(condition, il::expr_const(0, 1)).unwrap(),
        )
        .unwrap();

    control_flow_graph
        .unconditional_edge(lt_index, tail_index)
        .unwrap();
    control_flow_graph
        .unconditional_edge(gt_index, tail_index)
        .unwrap();

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
    assert!(
        du[&il::RefProgramLocation::new(
            &function,
            il::RefFunctionLocation::Instruction(block, block.instruction(0).unwrap())
        )
        .into()]
            .len()
            == 3
    );

    let block = function.control_flow_graph().block(0).unwrap();
    assert!(
        du[&il::RefProgramLocation::new(
            &function,
            il::RefFunctionLocation::Instruction(block, block.instruction(1).unwrap())
        )
        .into()]
            .len()
            == 1
    );

    let block = function.control_flow_graph().block(1).unwrap();
    assert!(
        du[&il::RefProgramLocation::new(
            &function,
            il::RefFunctionLocation::Instruction(block, block.instruction(0).unwrap())
        )
        .into()]
            .len()
            == 1
    );

    let block = function.control_flow_graph().block(0).unwrap();
    assert!(du[&il::RefProgramLocation::new(
        &function,
        il::RefFunctionLocation::Instruction(block, block.instruction(1).unwrap())
    )
    .into()]
        .contains(
            &il::RefProgramLocation::new(
                &function,
                il::RefFunctionLocation::Instruction(
                    function.control_flow_graph().block(1).unwrap(),
                    function
                        .control_flow_graph()
                        .block(1)
                        .unwrap()
                        .instruction(0)
                        .unwrap()
                )
            )
            .into()
        ));
}
