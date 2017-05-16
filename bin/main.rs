extern crate base64;
extern crate clap;
// #[macro_use]
// extern crate dyon;
#[macro_use]
extern crate error_chain;
extern crate falcon;
// #[macro_use] extern crate ketos;
// #[macro_use] extern crate ketos_derive;
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


fn label_value_set(ref mut control_flow_graph: &mut il::ControlFlowGraph, endian: Endian)
-> Result<()> {
    let cfg = control_flow_graph.clone();
    let analysis = Analysis::new(&cfg)?;
    let value_sets = analysis.value_set(32, endian)?;

    for (al, assignments) in value_sets {
        match al {
            AnalysisLocation::Instruction(il) => {
                let comment = il.find(&control_flow_graph)?
                                .variables_read()
                                .iter()
                                .map(|var_read| {
                                    format!(
                                        "{}={}",
                                        var_read.name(),
                                        match assignments.get(var_read) {
                                            Some(lv) => format!("{}", lv),
                                            None => String::from("?")
                                        }
                                    )
                                })
                                .collect::<Vec<String>>()
                                .join(", ");
                il.find_mut(control_flow_graph)?
                  .set_comment(Some(comment));
            },
            AnalysisLocation::Edge(el) => {
                let comment = match el.find(&control_flow_graph)?
                                      .condition() {
                    &Some(ref condition) => Some(condition.collect_variables()
                                                .iter()
                                                .map(|v| {
                                                    format!(
                                                        "{}={}",
                                                        v.name(),
                                                        match assignments.get(v) {
                                                            Some(lv) => format!("{}", lv),
                                                            None => String::from("?")
                                                        }
                                                    )
                                                })
                                                .collect::<Vec<String>>()
                                                .join(", ")),
                    &None => None
                };
                el.find_mut(control_flow_graph)?
                  .set_comment(comment);
            }
            _ => {},
        }
    }

    Ok(())
}


fn label_def_use(ref mut control_flow_graph: &mut il::ControlFlowGraph)
-> Result<()> {
    let cfg = control_flow_graph.clone();
    let analysis = Analysis::new(&cfg)?;
    let def_use = analysis.def_use();
    // let def_use = analysis.use_def();

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


fn run () -> Result<()> {
    let filename = Path::new("test_binaries/Palindrome/Palindrome.json");
    let elf = falcon::loader::json::Json::from_file(filename)?;

    let program = elf.to_program()?;

    println!("{}", program);


    if let Some(function) = program.function(0x80488CA) {
        let control_flow_graph = ssa(function.control_flow_graph().clone())?;
        let analysis = Analysis::new(&control_flow_graph)?;
        // let mut control_flow_graph = analysis.dead_code_elimination()?;
        let mut control_flow_graph = analysis.optimize()?;
        // let mut control_flow_graph = analysis.control_flow_graph().clone();
        // let mut control_flow_graph = analysis.simplification()?;

        let block_index = {
            let mut block = control_flow_graph.new_block()?;

            block.assign(il::var("esp", 32), il::expr_const(0xC0000000, 32));
            block.assign(il::var("DF", 1), il::expr_const(0x0, 1));

            block.index()
        };

        let entry = control_flow_graph.entry().unwrap();

        control_flow_graph.unconditional_edge(block_index, entry)?;
        control_flow_graph.set_entry(block_index)?;

        // label_value_set(&mut control_flow_graph, elf.architecture()?.endian().clone().into())?;
        label_def_use(&mut control_flow_graph)?;

        let mut file = File::create("/tmp/check.dot")?;
        file.write_all(&control_flow_graph.graph().dot_graph().into_bytes())?;

        /*
        let value_sets = analysis.value_set_analysis(16, elf.architecture()?.endian().into())?;

        for (al, assignments) in value_sets {
            match al {
                AnalysisLocation::Instruction(il) => {
                    if let Some(esp) = assignments.get(&il::var("esp", 32)) {
                        println!("{} esp={}", il, esp);
                    }
                }
                AnalysisLocation::Edge(el) => {
                    if let Some(esp) = assignments.get(&il::var("esp", 32)) {
                        println!("{} esp={}", el, esp);
                    }
                }
                _ => {}
            }
        }
        */

    }

    /*
    let matches = App::new("Falcon")
                    .version("0.0.1")
                    .author("Alex Eubanks <endeavor@rainbowsandpwnies.com>")
                    .about("Static Analysis Framework for Binaries")
                    .arg(Arg::with_name("script")
                        .short("s")
                        .value_name("SCRIPT")
                        .help("Path to script to execute")
                        .takes_value(true)
                        .required(true))
                    .get_matches();

    let script_filename = matches.value_of("script").unwrap();

    let mut script_file = File::open(script_filename)?;
    let mut script_string = String::new();
    script_file.read_to_string(&mut script_string)?;
    script_engine::run(&script_string);
    */
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