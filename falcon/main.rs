#![allow(dead_code, unused_variables)]

extern crate base64;
extern crate capstone_rust;
#[macro_use] extern crate error_chain;

pub mod analysis;
pub mod graph;
pub mod il;
pub mod translator;

use analysis::analysis_location::{set_string};
use analysis::analysis_location::AnalysisLocation::*;

use std::fs::File;
use std::io::Write;


mod error {
    error_chain! {
        types {
            Error, ErrorKind, ResultExt, Result;
        }

        errors {
            Sort
        }
    }
}


fn main () {
    let x86 = translator::x86();

    let example_function_base64 = "VYnlV1ZTg+TwgewQBAAAi0UMiUQkDGWhFAAAAImEJAwEAAAxwI1cJCS4AAAAALr6AAAAid+J0fOrxwQkDwsAAOj5/f//iUQkHIN8JBwAeQe4/////+tyxwQkA4wECOiN+///x0QkBO6JBAjHBCQOAAAA6Bn7///HBCQeAAAA6B37///HRCQI6AMAAI1EJCSJRCQEi0QkHIkEJOjR+v//hcB/E8cEJBuMBAjoQfv//7j/////6xONRCQkiUQkIItEJCD/0LgAAAAAi7QkDAQAAGUzNRQAAAB0BejS+v//jWX0W15fXcNmkGaQZpBmkGaQVVcx/1ZT6OX7//+BwwUVAACD7ByLbCQwjbMM////6BX6//+Ngwj///8pxsH+AoX2dCeNtgAAAACLRCQ4iSwkiUQkCItEJDSJRCQE/5S7CP///4PHATn3dd+DxBxbXl9dw+sNkJCQkJCQkJCQkJA=";
    let example_function = base64::decode(example_function_base64).unwrap();

    let mut function = x86.translate_function(&example_function, 0x804a00).unwrap();
    let mut control_flow_graph = function.control_flow_graph_mut();

    //control_flow_graph.ssa().unwrap();

    let analysis = analysis::Analysis::initialize(control_flow_graph).unwrap();
    let control_flow_graph = analysis.dead_code_elimination().unwrap();
    let analysis = analysis::Analysis::initialize(&control_flow_graph).unwrap();

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

    let dot = analysis.dead_code_elimination()
                      .unwrap()
                      .graph()
                      .dot_graph();

    let mut file = File::create("/tmp/falcon_post.dot").unwrap();
    file.write_all(dot.as_bytes()).unwrap();

    let dot = analysis.control_flow_graph()
                      .graph()
                      .dot_graph();

    let mut file = File::create("/tmp/falcon_pre.dot").unwrap();
    file.write_all(dot.as_bytes()).unwrap();
}