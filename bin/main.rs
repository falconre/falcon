#![allow(dead_code)]
#![deny(unused_must_use)]

extern crate base64;
extern crate bincode;
extern crate clap;
#[macro_use]
extern crate error_chain;
extern crate falcon;
// #[macro_use]
extern crate log;

// mod script_engine;

// use clap::{Arg, App};
use falcon::analysis::*;
use falcon::il;
use falcon::loader::Loader;
use log::{LogRecord, LogLevel, LogLevelFilter, LogMetadata};
use std::path::Path;


pub mod error {
    error_chain! {
        types {
            Error, ErrorKind, ResultExt, Result;
        }

        foreign_links {
            Base64Decode(::base64::DecodeError);
            Bincode(::bincode::Error);
            Falcon(::falcon::error::Error);
            Io(::std::io::Error);
        }
    }
}


use error::*;

// use analysis::analysis_location::AnalysisLocation::*;
// use analysis::lattice::*;

// use log::{LogRecord, LogLevel, LogLevelFilter, LogMetadata};
use std::fs::File;
use std::io::Write;


struct StdoutLogger;

impl log::Log for StdoutLogger {
    fn enabled(&self, metadata: &LogMetadata) -> bool {
        metadata.level() <= LogLevel::Trace
    }

    fn log(&self, record: &LogRecord) {
        if self.enabled(record.metadata()) {
            println!("{} - {}", record.level(), record.args());
        }
    }
}


fn label_value_set(
    ref mut control_flow_graph: &mut il::ControlFlowGraph,
    endian: ::falcon::analysis::Endian
) -> Result<()> {
    println!("label_value_set");
    let cfg = control_flow_graph.clone();
    let analysis = Analysis::new(&cfg)?;
    let value_sets = analysis.value_set(128, endian)?;

    for (al, assignments) in value_sets {
        match al {
            AnalysisLocation::Instruction(il) => {
                let comment = il.find(&control_flow_graph)?
                                .variables_read()
                                .iter()
                                .fold(Vec::new(), |mut v, var_read| {
                                    let mv = var_read.multi_var_clone();
                                    if let il::MultiVar::Scalar(scalar) = mv {
                                        v.push(format!(
                                            "{}={}",
                                            scalar.name(),
                                            match assignments.get(&scalar) {
                                                Some(lv) => format!("{}", lv),
                                                None => String::from("?")
                                            }
                                        ))
                                    }
                                    v
                                })
                                .join(", ");
                il.find_mut(control_flow_graph)?
                  .set_comment(Some(comment));
            },
            AnalysisLocation::Edge(el) => {
                let comment = match el.find(&control_flow_graph)
                                      .unwrap()
                                      .condition() {
                    &Some(ref condition) => Some(condition.collect_scalars()
                                                .iter()
                                                .map(|s| {
                                                    format!(
                                                        "{}={}",
                                                        s.name(),
                                                        match assignments.get(s) {
                                                            Some(lv) => format!("{}", lv),
                                                            None => String::from("?")
                                                        }
                                                    )
                                                })
                                                .collect::<Vec<String>>()
                                                .join(", ")),
                    &None => None
                };
                el.find_mut(control_flow_graph)
                  .unwrap()
                  .set_comment(comment);
            }
            _ => {},
        }
    }

    Ok(())
}


fn label_def_use(ref mut control_flow_graph: &mut il::ControlFlowGraph)
-> Result<()> {
    println!("label def_use");
    let cfg = control_flow_graph.clone();
    let analysis = Analysis::new(&cfg)?;
    let def_use = analysis.def_use();

    for (def, uses) in def_use {
        match *def {
            AnalysisLocation::Instruction(ref il) => {
                let comment = uses.iter()
                                  .map(|al| format!("{}", al))
                                  .collect::<Vec<String>>()
                                  .join(", ");
                il.find_mut(control_flow_graph)?
                  .set_comment(Some(comment));
            },
            _ => {},
        }
    }

    Ok(())
}


// fn label_constraints(ref mut control_flow_graph: &mut il::ControlFlowGraph)
// -> Result<()> {
//     println!("label_constraints");
//     let cfg = control_flow_graph.clone();
//     let analysis = Analysis::new(&cfg)?;
//     let constraints = analysis.constraints()?;

//     for (al, constraints) in constraints {
//         let comment = constraints.variable_constraints().iter()
//             .map(|constraint| {
//                 let al = constraint.0;
//                 let expr = constraint.1;
//                 format!("{} {}", al, expr)
//             })
//             .collect::<Vec<String>>()
//             .join(", ");
//         let comment = comment + " / " + &constraints.memory_constraints()
//             .iter()
//             .map(|memory_constraint| {
//                 let al = memory_constraint.0;
//                 let ref address = (memory_constraint.1).0;
//                 let ref expr = (memory_constraint.1).1;
//                 format!("{} [{}] # {}", al, address, expr)
//             })
//             .collect::<Vec<String>>()
//             .join(", ");
//         println!("{} {}", al, comment);
//         match al {
//             AnalysisLocation::Edge(ref el) => {
//                 el.find_mut(control_flow_graph)?
//                   .set_comment(Some(comment));
//             }
//             AnalysisLocation::Instruction(ref il) => {
//                 il.find_mut(control_flow_graph)?
//                   .set_comment(Some(comment));
//             }
//             _ => {}
//         }
//     }

//     Ok(())
// }


fn run () -> Result<()> {
    //let filename = Path::new("test_binaries/Palindrome/Palindrome.json");
    //let elf = falcon::loader::json::Json::from_file(filename)?;

    let filename = Path::new("test_binaries/simple-0/simple-0");
    let mut elf = falcon::loader::elf::Elf::from_file(filename)?;

    elf.add_user_function(0x804849b);

    let program = elf.to_program()?;

    if let Some(function) = program.function_by_address(0x804849b) {
        let analysis = Analysis::new(function.control_flow_graph())?;
        let mut control_flow_graph = analysis.dead_code_elimination()?;
        // let mut control_flow_graph = analysis.optimize()?;
        // let mut control_flow_graph = analysis.control_flow_graph().clone();
        // let mut control_flow_graph = analysis.simplification()?;

        let block_index = {
            let mut block = control_flow_graph.new_block()?;

            block.assign(il::scalar("esp", 32), il::expr_const(0xC0000000, 32));
            block.assign(il::scalar("DF", 1), il::expr_const(0x0, 1));

            block.index()
        };

        let entry = control_flow_graph.entry().unwrap();

        control_flow_graph.unconditional_edge(block_index, entry)?;
        control_flow_graph.set_entry(block_index)?;

        let control_flow_graph = ssa(control_flow_graph)?;

        // label_value_set(&mut control_flow_graph, elf.architecture()?.endian().clone().into())?;
        // label_def_use(&mut control_flow_graph)?;
        // label_constraints(&mut control_flow_graph)?;

        println!("Writing graph\n");
        let mut file = File::create("/tmp/check.dot")?;
        file.write_all(&control_flow_graph.graph().dot_graph().into_bytes())?;

        let mut file = File::create("/tmp/check.bincode")?;
        file.write_all(&bincode::serialize(&control_flow_graph, bincode::Infinite)?)?;
    }

    Ok(())
}



fn main () {
    // initialize logging
    log::set_logger(|max_log_level| {
        max_log_level.set(LogLevelFilter::Trace);
        Box::new(StdoutLogger)
    }).unwrap();

    // symex::engine_test().unwrap();
    run().unwrap();
}