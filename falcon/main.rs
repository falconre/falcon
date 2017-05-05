#![allow(dead_code, unused_variables)]

extern crate base64;
#[macro_use]
extern crate bitflags;
extern crate capstone_rust;
#[macro_use]
extern crate error_chain;
extern crate goblin;
// #[macro_use]
// extern crate ketos;
#[macro_use]
extern crate log;



pub mod analysis;
pub mod executor;
pub mod graph;
pub mod il;
pub mod loader;
pub mod translator;

// use analysis::analysis_location::{set_string};

use analysis::analysis_location::AnalysisLocation::*;
use analysis::lattice::*;

use log::{LogRecord, LogLevel, LogLevelFilter, LogMetadata};
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


mod error {
    error_chain! {
        types {
            Error, ErrorKind, ResultExt, Result;
        }

        foreign_links {
            Goblin(::goblin::error::Error);
            Io(::std::io::Error);
        }

        errors {
            Sort
            Arithmetic
        }
    }
}

use error::*;


fn run () -> Result<()> {
    // Create a new x86 translator
    let x86 = translator::x86();

    // Load some bytes for our example function
    let example_function_base64 = "VYnlV1ZTg+TwgewQBAAAi0UMiUQkDGWhFAAAAImEJAwEAAAxwI1cJCS4AAAAALr6AAAAid+J0fOrxwQkDwsAAOj5/f//iUQkHIN8JBwAeQe4/////+tyxwQkA4wECOiN+///x0QkBO6JBAjHBCQOAAAA6Bn7///HBCQeAAAA6B37///HRCQI6AMAAI1EJCSJRCQEi0QkHIkEJOjR+v//hcB/E8cEJBuMBAjoQfv//7j/////6xONRCQkiUQkIItEJCD/0LgAAAAAi7QkDAQAAGUzNRQAAAB0BejS+v//jWX0W15fXcNmkGaQZpBmkGaQVVcx/1ZT6OX7//+BwwUVAACD7ByLbCQwjbMM////6BX6//+Ngwj///8pxsH+AoX2dCeNtgAAAACLRCQ4iSwkiUQkCItEJDSJRCQE/5S7CP///4PHATn3dd+DxBxbXl9dw+sNkJCQkJCQkJCQkJA=";
    let example_function = base64::decode(example_function_base64).unwrap();

    // Lift the function into Falcon IL
    println!("Lifting");
    let mut function = x86.translate_function(&example_function, 0x804a00).unwrap();

    // Get the function's ControlFlowGraph
    let mut control_flow_graph = function.control_flow_graph_mut();

    // We are going to add some values here for sanity's sake by
    // 1. Creating a new block
    // 2. Add some initial value assignments to that block
    // 3. Creating an edge from our new block to the entry of the CFG
    // 4. Setting the new entry of the CFG to our block
    let block_index = {
        let mut block = control_flow_graph.new_block()?;

        block.assign(il::var("esp", 32), il::expr_const(0xb0000000, 32));
        block.assign(il::var("DF", 1), il::expr_const(0, 1));

        block.index()
    };

    let entry = control_flow_graph.entry().unwrap();
    control_flow_graph.unconditional_edge(block_index, entry)?;
    control_flow_graph.set_entry(block_index)?;

    // Initialize our analysis
    let analysis = analysis::Analysis::initialize(&control_flow_graph)?;
    // Get a new CFG with dead code eliminated
    let control_flow_graph = analysis.dead_code_elimination()?;
    // Perform analysis over our dead code-free CFG
    let analysis = analysis::Analysis::initialize(&control_flow_graph)?;

    println!("Calculating Value Sets");
    let value_sets = analysis.value_set_analysis(64).unwrap();

    let mut control_flow_graph = control_flow_graph.clone();

    for al in value_sets {
        let this_location = al.0;
        let value_sets = al.1;
        match this_location {
            Edge(ref el) => {
                trace!("setting comment for edge {}", el.find(&control_flow_graph)?);
                let comment = match *el.find(&control_flow_graph)?
                                       .condition() {
                    Some(ref condition) => {
                        Some(condition.collect_variables()
                                      .iter()
                                      .map(|var| {
                                           let meet = LatticeValue::Meet;
                                           let value = match value_sets.get(var) {
                                               Some(value) => value,
                                               None => &meet
                                           };
                                           format!("{}={}", var, value)
                                      })
                                      .collect::<Vec<String>>()
                                      .join(", ")
                        )
                    },
                    None => None
                };
                if let Some(comment) = comment {
                    let ref mut edge = el.find_mut(&mut control_flow_graph)?;
                    edge.set_comment(comment);
                }
            },
            Instruction(ref il) => {
                trace!("setting comment for instruction {}", il.find(&control_flow_graph)?);
                let ref mut instruction = il.find_mut(&mut control_flow_graph)?;
                let comment = instruction.variables_read()
                                         .iter()
                                         .map(|var| {
                                            let meet = LatticeValue::Meet;
                                            let value = match value_sets.get(var) {
                                                Some(value) => value,
                                                None => &meet
                                            };
                                            format!("{}={}", var, value)
                                         })
                                         .collect::<Vec<String>>()
                                         .join(", ");
                instruction.set_comment(comment);
            },
            EmptyBlock(_) => {}
        }
    }

    /*
    let rd = analysis.reaching_definitions();
    let ud = analysis.use_def();
    let du = analysis.def_use();

    for reach in rd {
        let analysis_location = reach.0;
        println!("rd {}: {}", analysis_location, rd[analysis_location]);
        println!("ud {}: {}", analysis_location, set_string(&ud[analysis_location]));
        println!("du {}: {}", analysis_location, set_string(&du[analysis_location]));
        println!("");
    }

    for al in ud {
        let this_location = al.0;
        let comment = set_string(al.1);
        match this_location {
            &Edge(ref el) => el.find_mut(control_flow_graph)
                               .unwrap()
                               .set_comment(comment),
            &Instruction(ref il) => il.find_mut(control_flow_graph)
                                      .unwrap()
                                      .set_comment(comment)
        }
    }
    */

    
    let dot = control_flow_graph.graph()
                                .dot_graph();


    let mut file = File::create("/tmp/falcon.dot").unwrap();
    file.write_all(dot.as_bytes()).unwrap();

    Ok(())
}


fn main () {
    // initialize logging
    log::set_logger(|max_log_level| {
        max_log_level.set(LogLevelFilter::Trace);
        Box::new(StdoutLogger)
    }).unwrap();

    run().unwrap();
}