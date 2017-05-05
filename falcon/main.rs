#![allow(dead_code, unused_variables)]

extern crate base64;
extern crate capstone_rust;
#[macro_use] extern crate error_chain;
#[macro_use] extern crate log;

pub mod analysis;
pub mod executor;
pub mod graph;
pub mod il;
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
        metadata.level() <= LogLevel::Info
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

        errors {
            Sort
            Arithmetic
        }
    }
}


fn main () {
    // initialize logging
    log::set_logger(|max_log_level| {
        max_log_level.set(LogLevelFilter::Info);
        Box::new(StdoutLogger)
    }).unwrap();

    let x86 = translator::x86();

    let example_function_base64 = "VYnlV1ZTg+TwgewQBAAAi0UMiUQkDGWhFAAAAImEJAwEAAAxwI1cJCS4AAAAALr6AAAAid+J0fOrxwQkDwsAAOj5/f//iUQkHIN8JBwAeQe4/////+tyxwQkA4wECOiN+///x0QkBO6JBAjHBCQOAAAA6Bn7///HBCQeAAAA6B37///HRCQI6AMAAI1EJCSJRCQEi0QkHIkEJOjR+v//hcB/E8cEJBuMBAjoQfv//7j/////6xONRCQkiUQkIItEJCD/0LgAAAAAi7QkDAQAAGUzNRQAAAB0BejS+v//jWX0W15fXcNmkGaQZpBmkGaQVVcx/1ZT6OX7//+BwwUVAACD7ByLbCQwjbMM////6BX6//+Ngwj///8pxsH+AoX2dCeNtgAAAACLRCQ4iSwkiUQkCItEJDSJRCQE/5S7CP///4PHATn3dd+DxBxbXl9dw+sNkJCQkJCQkJCQkJA=";
    let example_function = base64::decode(example_function_base64).unwrap();

    println!("Lifting");
    let mut function = x86.translate_function(&example_function, 0x804a00).unwrap();
    let control_flow_graph = function.control_flow_graph_mut();

    //control_flow_graph.ssa().unwrap();

    let analysis = analysis::Analysis::initialize(control_flow_graph).unwrap();
    let control_flow_graph = analysis.dead_code_elimination().unwrap();
    let analysis = analysis::Analysis::initialize(&control_flow_graph).unwrap();

    println!("Calculating Value Sets");
    let value_sets = analysis.value_set_analysis(32).unwrap();

    let mut control_flow_graph = control_flow_graph.clone();

    for al in value_sets {
        let this_location = al.0;
        let value_sets = al.1;
        match this_location {
            Edge(_) => {},
            Instruction(ref il) => {
                let ref mut instruction = il.find_mut(&mut control_flow_graph)
                                        .unwrap();
                let comment = instruction.variables_read()
                                         .iter()
                                         .map(|v| {
                                            let meet = LatticeValue::Meet;
                                            let value = match value_sets.get(v) {
                                                Some(value) => value,
                                                None => &meet
                                            };
                                            format!("{} = {}", v, value)
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
}