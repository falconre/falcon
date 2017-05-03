#![allow(dead_code, unused_variables)]

extern crate base64;
extern crate capstone_rust;
#[macro_use] extern crate error_chain;

pub mod analysis;
pub mod graph;
pub mod il;
pub mod translator;

use analysis::reaching_definitions;

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
    println!("compute ssa");
    control_flow_graph.ssa().unwrap();
    println!("compute reaching defintions");
    let rd = reaching_definitions::compute(control_flow_graph).unwrap();
    println!("done");

    for def in rd.iter() {
        let comment = reaching_definitions::reaches_to_string_with_var(
            &def.1,
            &control_flow_graph
        ).unwrap();
        def.0
           .find_mut(&mut control_flow_graph).unwrap()
           .set_comment(comment);
    }

    let dot = control_flow_graph.graph().dot_graph();

    let mut file = File::create("/tmp/falcon_post.dot").unwrap();
    file.write_all(dot.as_bytes()).unwrap();
}