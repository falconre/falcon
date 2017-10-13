//! A layer of abstraction over a SMT solver

use symbolic::util::*;
use error::*;
use il;
use regex;
use std::collections::BTreeSet;
use std::io::{Read, Write};
use std::process;

// pub struct Solver {
//     child: process::Child
// }

pub struct Solver;


impl Solver {
    pub fn new() -> Result<Solver> {
        // let mut child = process::Command::new("z3")
        //     .arg("-in")
        //     .stdin(process::Stdio::piped())
        //     .stdout(process::Stdio::piped())
        //     .stderr(process::Stdio::piped())
        //     .spawn()
        //     .expect("Failed to invoke solver");

        // if let Some(ref mut stdin) = child.stdin {
        //     stdin.write("(set-option :produce-models true)\n".as_bytes())?;
        //     stdin.write("(set-logic QF_AUFBV)\n".as_bytes())?;
        //     stdin.write("(set-info :smt-lib-version 2.0)\n".as_bytes())?;
        // }
        // else {
        //     bail!("Failed to get stdout for child");
        // }
        
        // Ok(Solver {
        //     child: child
        // })
        
        Ok(Solver)
    }


    pub fn get_child(&mut self) -> Result<process::Child> {
        let mut child = process::Command::new("z3")
            .arg("-in")
            .stdin(process::Stdio::piped())
            .stdout(process::Stdio::piped())
            .stderr(process::Stdio::piped())
            .spawn()
            .expect("Failed to invoke solver");

        if let Some(ref mut stdin) = child.stdin {
            stdin.write("(set-option :produce-models true)\n".as_bytes())?;
            stdin.write("(set-logic QF_AUFBV)\n".as_bytes())?;
            stdin.write("(set-info :smt-lib-version 2.0)\n".as_bytes())?;
        }
        else {
            bail!("Failed to get stdout for child");
        }

        Ok(child)
    }


    pub fn cleanup_child(&mut self, child: &mut process::Child) -> Result<()> {
        child.kill().expect("Failed to kill solver during drop");
        child.wait().expect("Error waiting on solver after drop kill");

        Ok(())
    }


    pub fn solve(&mut self, expr: &il::Expression, constraints: Vec<il::Expression>)
    -> Result<Option<il::Constant>> {

        // We need to collect all of the scalars so we can declare them
        let mut scalars: BTreeSet<(String, usize)> = BTreeSet::new();

        // Collect all scalars from constraints
        for constraint in &constraints {
            for scalar in constraint.collect_scalars() {
                scalars.insert((scalar.name().to_string(), scalar.bits()));
            }
        }

        // And all scalars from the expression we are solving
        for scalar in expr.collect_scalars() {
            scalars.insert((scalar.name().to_string(), scalar.bits()));
        }

        // And a scalar for our result
        scalars.insert(("EVAL_RESULT".to_string(), expr.bits()));

        // Push state
        let mut solver_lines = vec!["(push)".to_string()];

        // Declare all variables
        for scalar in scalars {
            solver_lines.push(format!("(declare-fun {} () (_ BitVec {}))",
                scalar.0, scalar.1));
        }

        // Assert Constraints
        for constraint in constraints {
            solver_lines.push(format!("(assert (= #b1 {}))",
                expr_to_smtlib2(&constraint)));
        }

        // Assert the expression
        solver_lines.push(format!("(assert (= EVAL_RESULT {}))",
            expr_to_smtlib2(expr)));

        // Get value and pop this state
        solver_lines.push("(check-sat)".to_string());
        solver_lines.push("(get-value (EVAL_RESULT))".to_string());
        solver_lines.push("(pop)\n".to_string());

        let solver_input = solver_lines.join("\n");

        let mut child = self.get_child()?;

        // match self.child.stdin {
        match child.stdin {
            Some(ref mut stdin) => {
                stdin.write_all(solver_input.as_bytes())?;
                stdin.flush()?;
            },
            None => {
                self.cleanup_child(&mut child)?;
                bail!("Failed to get stdin from solver process")
            }
        }

        for _ in 0..5 {
            let mut buf = [0; 2048];

            // read from stdout
            // let bytes_read = match self.child.stdout {
            let bytes_read = match child.stdout {
                Some(ref mut stdout) => stdout.read(&mut buf)?,
                None => {
                    self.cleanup_child(&mut child)?;
                    bail!("Failed to get stdout from solver proces")
                }
            };

            let buf = if bytes_read == 0 {
                self.cleanup_child(&mut child)?;
                bail!("Read 0 bytes from solver")
            } else {
                buf.split_at(bytes_read).0.to_vec()
            };

            let solver_output = String::from_utf8(buf)?;

            // check if we got unsat
            if solver_output.contains("unsat") {
                self.cleanup_child(&mut child)?;
                return Ok(None);
            }

            lazy_static!{
                static ref RE16: regex::Regex = regex::Regex::new("EVAL_RESULT #x([0-9a-f]+)").unwrap();
                static ref RE2: regex::Regex = regex::Regex::new("EVAL_RESULT #b([0-1]+)").unwrap();
            }

            // check for base16-encoded value
            if let Some(caps) = RE16.captures(&solver_output) {
                let value = u64::from_str_radix(&caps[1], 16)?;
                self.cleanup_child(&mut child)?;
                return Ok(Some(il::const_(value, expr.bits())));
            }

            // check for base2-encoded value
            if let Some(caps) = RE2.captures(&solver_output) {
                let value = u64::from_str_radix(&caps[1], 2)?;
                self.cleanup_child(&mut child)?;
                return Ok(Some(il::const_(value, expr.bits())));
            }

        }

        self.cleanup_child(&mut child)?;
        bail!("Read from solver 5 times, did not find a result");
    }
}


impl Clone for Solver {
    fn clone(&self) -> Solver {
        Solver::new().expect("Failed to create new Solver while cloning Solver")
    }
}


impl Default for Solver {
    fn default() -> Solver {
        Solver::new().unwrap()
    }
}


impl Drop for Solver {
    fn drop(&mut self) {
        // self.child.kill().expect("Failed to kill solver during drop");
        // self.child.wait().expect("Error waiting on solver after drop kill");
    }
}

impl ::std::fmt::Debug for Solver {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        write!(f, "solver")
    }
}