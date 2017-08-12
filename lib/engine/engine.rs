//! A Symbolic Execution engine for Falcon IL.
//!
//! `SymbolicEngine` represents one symbolic state in the program. It is not a complete
//! symbolic execution engine, we still need other pieces such as `EngineDriver`. We execute
//! operations over the `SymbolicEngine` to receive a variable number of `SymbolicSuccessor`s
//! in return. Each `SymbolicSuccessor` has a type representing how control flow should
//! behave.

use engine::memory::SymbolicMemory;
use error::*;
use executor;
use il;
use regex;
use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::process;
use translator::TranslationMemory;


/// The type of successor from execution of an `Operation` over a `SymbolicEngine`.
#[derive(Clone)]
pub enum SuccessorType {
    /// Control flow should contine normally, with no special considerations.
    FallThrough,
    /// Control flow should branch to the given address.
    Branch(u64),
    /// A `Platform` must handle a `Raise` instruction, and then control flow
    /// should continue normally.
    Raise(il::Expression)
}


/// A `SymbolicSuccessor` is the result of executing an `Operation` over a
/// `SymbolicEngine`.
#[derive(Clone)]
pub struct SymbolicSuccessor {
    type_: SuccessorType,
    engine: SymbolicEngine
}


impl SymbolicSuccessor {
    fn new(engine: SymbolicEngine, type_: SuccessorType)
        -> SymbolicSuccessor {

        SymbolicSuccessor {
            engine: engine,
            type_: type_
        }
    }

    /// Get the type of this `SymbolicSuccessor`.
    pub fn type_(&self) -> &SuccessorType {
        &self.type_
    }

    /// Consume this `SymbolicSuccessor` and turn it into a `SymbolicEngine`.
    pub fn into_engine(self) -> SymbolicEngine {
        self.engine
    }
}


/// An engine for maintaining a symbolic state, performing operations over that
/// state, and querying that state.
#[derive(Clone)]
pub struct SymbolicEngine {
    scalars: BTreeMap<String, il::Expression>,
    memory: SymbolicMemory,
    constraints: Vec<il::Expression>,
}


impl SymbolicEngine {
    /// Create a new `SymbolicEngine`
    pub fn new(memory: SymbolicMemory) -> SymbolicEngine {
        SymbolicEngine {
            scalars: BTreeMap::new(),
            memory: memory,
            constraints: Vec::new(),
        }
    }

    /// Get the `SymbolicMemory` backing this engine.
    pub fn memory(&self) -> &SymbolicMemory {
        &self.memory
    }

    /// Get a mutable reference to the `SymbolicMemory` backing this reference.
    pub fn memory_mut(&mut self) -> &mut SymbolicMemory {
        &mut self.memory
    }


    pub fn constraints(&self) -> &Vec<il::Expression> {
        &self.constraints
    }


    /// Add constraint to this state.
    ///
    /// This constraint must be equal to 0x1:1, or a 1-bit value of 1, for the
    /// state to be satisfiable. This is the result of Falcon IL comparison
    /// expressions.
    ///
    /// It is an error to add a constraint that is unsatisfiable in the engine's
    /// current state.
    pub fn add_constraint(&mut self, mut constraint: il::Expression)
        -> Result<()> {

        constraint = self.symbolize_expression(&constraint)?;
        if all_constants(&constraint) {
            // If we have a constant constraint which is always 0, add a constant
            // constraint which is always 0.
            if executor::constants_expression(&constraint)?.value() != 1 {
                self.constraints.push(il::Expression::cmpeq(
                    il::expr_const(0, 1),
                    il::expr_const(1, 1)
                )?);
            }
        }
        else {
            self.constraints.push(constraint);
        }

        Ok(())
    }


    /// Set a symbolic scalar
    pub fn set_scalar<S>(&mut self, name: S, value: il::Expression)
        where S: Into<String> {
        self.scalars.insert(name.into(), value);
    }


    /// Get the symbolic value of a scalar
    pub fn get_scalar(&self, name: &str) -> Option<&il::Expression> {
        self.scalars.get(name)
    }


    /// Replace scalars in the expression with those in the engine's current
    /// scalar to expression mapping, and if all scalars are currently constant,
    /// evaluate to constant and return that. Otherwise, return expression with
    /// symbolic values
    pub fn symbolize_and_eval(&self, expression: &il::Expression)
        -> Result<il::Expression> {

        let expression = self.symbolize_expression(expression)?;
        if all_constants(&expression) {
            let constant = executor::constants_expression(&expression)?;
            Ok(il::Expression::Constant(constant))
        }
        else {
            Ok(expression)
        }
    }

    /// Replaces scalars in the expression with those in the engine's current
    /// scalar to expression mapping, and then evaluates for a concrete value.
    /// 
    /// Returns None is there is no satisfiable solution, or a concrete value as
    /// a constant if a concrete solution exists.
    pub fn symbolize_and_concretize(
        &self,
        expression: &il::Expression,
        mut constraints: Option<Vec<il::Expression>>
    ) -> Result<Option<il::Constant>> {

        let expression = self.symbolize_expression(expression)?;

        constraints = match constraints {
            None => None,
            Some(constraints) => Some(constraints
                .iter()
                .map(|constraint| self.symbolize_expression(&constraint).unwrap())
                .collect::<Vec<il::Expression>>())
        };

        if let Some(ref constraints) = constraints {
            for constraint in constraints {
                if !all_constants(&constraint) {
                    return self.eval(&expression, Some(constraints.to_vec()))
                }
                if executor::constants_expression(&constraint)?.value() != 1 {
                    return Ok(None);
                }
            }
        }

        // At this point, constraints are all constants
        if all_constants(&expression) {
            Ok(Some(executor::constants_expression(&expression)?))
        }
        else {
            self.eval(&expression, constraints)
        }
    }


    /// Forks the state of the symbolic engine. In future iterations, this will
    /// allow for Copy-On-Write optimizations.
    pub fn fork(&self) -> SymbolicEngine {
        SymbolicEngine {
            scalars: self.scalars.clone(),
            memory: self.memory.clone(),
            constraints: self.constraints.clone()
        }
    }


    /// Takes a regular IL expression, and replaces scalars with their
    /// expression values using the engine's internal scalar store.
    pub fn symbolize_expression(&self, expression: &il::Expression)
        -> Result<il::Expression> {

        Ok(match *expression {
            il::Expression::Scalar(ref scalar) => {
                if self.scalars.contains_key(scalar.name()) {
                    self.scalars[scalar.name()].clone()
                }
                else {
                    il::Expression::Scalar(scalar.clone())
                }
            }
            il::Expression::Constant(_) => expression.clone(),
            il::Expression::Add(ref lhs, ref rhs) =>
                il::Expression::add(self.symbolize_expression(lhs)?,
                                    self.symbolize_expression(rhs)?)?,
            il::Expression::Sub(ref lhs, ref rhs) =>
                il::Expression::sub(self.symbolize_expression(lhs)?,
                                    self.symbolize_expression(rhs)?)?,
            il::Expression::Mul(ref lhs, ref rhs) =>
                il::Expression::mul(self.symbolize_expression(lhs)?,
                                    self.symbolize_expression(rhs)?)?,
            il::Expression::Divu(ref lhs, ref rhs) =>
                il::Expression::divu(self.symbolize_expression(lhs)?,
                                     self.symbolize_expression(rhs)?)?,
            il::Expression::Modu(ref lhs, ref rhs) =>
                il::Expression::modu(self.symbolize_expression(lhs)?,
                                     self.symbolize_expression(rhs)?)?,
            il::Expression::Divs(ref lhs, ref rhs) =>
                il::Expression::divs(self.symbolize_expression(lhs)?,
                                     self.symbolize_expression(rhs)?)?,
            il::Expression::Mods(ref lhs, ref rhs) =>
                il::Expression::mods(self.symbolize_expression(lhs)?,
                                     self.symbolize_expression(rhs)?)?,
            il::Expression::And(ref lhs, ref rhs) =>
                il::Expression::and(self.symbolize_expression(lhs)?,
                                    self.symbolize_expression(rhs)?)?,
            il::Expression::Or(ref lhs, ref rhs) =>
                il::Expression::or(self.symbolize_expression(lhs)?,
                                   self.symbolize_expression(rhs)?)?,
            il::Expression::Xor(ref lhs, ref rhs) =>
                il::Expression::xor(self.symbolize_expression(lhs)?,
                                    self.symbolize_expression(rhs)?)?,
            il::Expression::Shl(ref lhs, ref rhs) =>
                il::Expression::shl(self.symbolize_expression(lhs)?,
                                    self.symbolize_expression(rhs)?)?,
            il::Expression::Shr(ref lhs, ref rhs) =>
                il::Expression::shr(self.symbolize_expression(lhs)?,
                                    self.symbolize_expression(rhs)?)?,
            il::Expression::Cmpeq(ref lhs, ref rhs) =>
                il::Expression::cmpeq(self.symbolize_expression(lhs)?,
                                      self.symbolize_expression(rhs)?)?,
            il::Expression::Cmpneq(ref lhs, ref rhs) =>
                il::Expression::cmpneq(self.symbolize_expression(lhs)?,
                                       self.symbolize_expression(rhs)?)?,
            il::Expression::Cmplts(ref lhs, ref rhs) =>
                il::Expression::cmplts(self.symbolize_expression(lhs)?,
                                       self.symbolize_expression(rhs)?)?,
            il::Expression::Cmpltu(ref lhs, ref rhs) =>
                il::Expression::cmpltu(self.symbolize_expression(lhs)?,
                                       self.symbolize_expression(rhs)?)?,
            il::Expression::Zext(bits, ref src) =>
                il::Expression::zext(bits, self.symbolize_expression(src)?)?,
            il::Expression::Sext(bits, ref src) =>
                il::Expression::sext(bits, self.symbolize_expression(src)?)?,
            il::Expression::Trun(bits, ref src) =>
                il::Expression::trun(bits, self.symbolize_expression(src)?)?
        })
    }


    /// Evaluates an expression in the solver. If constraints are given, enforces
    /// these extra constraints.
    pub fn eval(
        &self,
        expr: &il::Expression,
        constraints: Option<Vec<il::Expression>>
    ) -> Result<Option<il::Constant>> {

        let mut solver_lines : Vec<String> = Vec::new();
        solver_lines.push("(set-option :produce-models true)".to_string());
        solver_lines.push("(set-logic QF_AUFBV)".to_string());
        solver_lines.push("(set-info :smt-lib-version 2.0)".to_string());

        let constraints = match constraints {
            Some(constraints) => {
                let mut c = Vec::new();
                for constraint in constraints {
                    c.push(self.symbolize_and_eval(&constraint)?);
                }
                c.append(&mut self.constraints.clone());
                c
            },
            None => self.constraints.clone()
        };

        // Collect all the scalars from our constraints
        let mut constraint_scalars: BTreeSet<(String, usize)> = BTreeSet::new();
        for constraint in &constraints {
            for scalar in constraint.collect_scalars() {
                constraint_scalars.insert(
                    (scalar.name().to_string(), scalar.bits())
                );
            }
        }

        // Add in scalars from our expression
        for scalar in expr.collect_scalars() {
            constraint_scalars.insert(
                (scalar.name().to_string(), scalar.bits())
            );
        }

        // Add in a special variable for this eval so we can get the result
        constraint_scalars.insert(("EVAL_RESULT".to_string(), expr.bits()));

        // Create all of our variable declarations
        for constraint_scalar in &constraint_scalars {
            solver_lines.push(format!("(declare-fun {} () (_ BitVec {}))",
                constraint_scalar.0, constraint_scalar.1));
        }

        // Assert our constraints
        for constraint in &constraints {
            solver_lines.push(format!("(assert (= #b1 {}))",
                expr_to_smtlib2(&constraint)));
        }

        // Assert this expression
        solver_lines.push(format!("(assert (= EVAL_RESULT {}))",
            expr_to_smtlib2(expr)));
        
        solver_lines.push("(check-sat)".to_string());
        solver_lines.push("(get-value (EVAL_RESULT))".to_string());

        let mut child = process::Command::new("z3")
            .arg("-in")
            .stdin(process::Stdio::piped())
            .stdout(process::Stdio::piped())
            .spawn()
            .expect("Failed to invoke solver");

        let solver_input = solver_lines.join("\n");
        match child.stdin {
            Some(ref mut stdin) => stdin.write_all(solver_input.as_bytes())?,
            None => bail!("Could not get stdin for solver process")
        };

        let output = child.wait_with_output()?;

        let solver_output = String::from_utf8(output.stdout)?;

        // println!("{}", solver_input);

        // println!("solver output: {}", solver_output);

        if solver_output.contains("unsat") || !solver_output.contains("sat") {
            return Ok(None);
        }

        lazy_static!{
            static ref RE16: regex::Regex = regex::Regex::new("EVAL_RESULT #x([0-9a-f]+)").unwrap();
            static ref RE2: regex::Regex = regex::Regex::new("EVAL_RESULT #b([0-1]+)").unwrap();
        }

        if let Some(caps) = RE16.captures(&solver_output) {
            let value = u64::from_str_radix(&caps[1], 16)?;
            return Ok(Some(il::const_(value, expr.bits())));
        }

        if let Some(caps) = RE2.captures(&solver_output) {
            let value = u64::from_str_radix(&caps[1], 2)?;
            return Ok(Some(il::const_(value, expr.bits())));
        }

        panic!("Couldn't parse EVAL_RESULT in {}", solver_output);
    }


    /// Loads a single byte from memory. This byte must have a concrete value.
    pub fn load_only_concrete(&self, address: u64) -> Result<Option<u8>> {
        let byte = self.memory.load(address, 8)?;
        let byte = match byte {
            Some(byte) => byte,
            None => return Ok(None)
        };

        if all_constants(&byte) {
            let value = executor::constants_expression(&byte)?;
            Ok(Some(value.value() as u8))
        }
        else {
            Ok(None)
        }
    }


    /// Gets the value of a scalar, but only if the scalar has a concrete value
    pub fn get_scalar_only_concrete(&self, name: &str) -> Result<Option<il::Constant>> {
        let expr = match self.get_scalar(name) {
            Some(expr) => expr,
            None => bail!("scalar {} does not exist", name)
        };

        if !all_constants(expr) {
            Ok(None)
        }
        else {
            Ok(Some(executor::constants_expression(expr)?))
        }
    }


    /// Determine whether the constraints of this state are satisfiable
    pub fn sat(&self, constraints: Option<Vec<il::Expression>>) -> Result<bool> {
        // An expression that will always evaluate to true
        let expression = il::Expression::cmpeq(
            il::expr_const(1, 1),
            il::expr_const(1, 1)
        ).unwrap();
        if self.eval(&expression, constraints)?.is_some() {
            Ok(true)
        }
        else {
            Ok(false)
        }
    }


    /// Execute an IL operation over the engine, updating state.
    pub fn execute(mut self, operation: &il::Operation)
        -> Result<Vec<SymbolicSuccessor>> {

        Ok(match *operation {
            il::Operation::Assign { ref dst, ref src } => {
                let src = self.symbolize_and_eval(src)?;
                self.set_scalar(dst.name(), src);
                vec![SymbolicSuccessor::new(self, SuccessorType::FallThrough)]
            },
            il::Operation::Store { ref index, ref src, .. } => {
                let src = self.symbolize_and_eval(src)?;
                let index = self.symbolize_and_concretize(index, None)?;
                if let Some(index) = index {
                    self.memory.store(index.value(), src)?;
                    vec![SymbolicSuccessor::new(self, SuccessorType::FallThrough)]
                }
                else {
                    Vec::new()
                }
            },
            il::Operation::Load { ref dst, ref index, .. } => {
                let index_ = self.symbolize_and_concretize(index, None)?;
                if let Some(index) = index_ {
                    let value = self.memory.load(index.value(), dst.bits())?;
                    match value {
                        Some(v) => {
                            self.scalars.insert(dst.name().to_string(), v.clone());
                            vec![SymbolicSuccessor::new(self, SuccessorType::FallThrough)]
                        },
                        None => {
                            trace!("Got invalid concretized load address 0x{:x}", index.value());
                            Vec::new()
                        }
                    }
                }
                else {
                    trace!("Could not resolve load address {}", index);
                    Vec::new()
                }
            },
            il::Operation::Brc { ref target, ref condition } => {
                let mut successors = Vec::new();
                // Is it possible for this case not to be taken?
                let null_case = il::Expression::cmpeq(condition.clone(), il::expr_const(0, 1))?;
                let r = self.symbolize_and_concretize(&null_case, Some(vec![null_case.clone()]))?;
                if r.is_some() {
                    let mut engine = self.fork();
                    engine.add_constraint(null_case)?;
                    let successor = SymbolicSuccessor::new(engine, SuccessorType::FallThrough);
                    successors.push(successor);
                }
                // This is the true case
                let r = self.symbolize_and_concretize(&condition, Some(vec![condition.clone()]))?;
                if r.is_some() {
                    let t = self.symbolize_and_concretize(target, Some(vec![condition.clone()]))?;
                    if let Some(target) = t {
                        let mut engine = self.fork();
                        engine.add_constraint(condition.clone())?;
                        let successor = SymbolicSuccessor::new(
                            engine,
                            SuccessorType::Branch(target.value())
                        );
                        successors.push(successor);
                    }
                }
                successors
            },
            il::Operation::Phi { .. } => {
                panic!("Phi unimplemented");
            },
            il::Operation::Raise { ref expr } => {
                vec![SymbolicSuccessor::new(
                    self,
                    SuccessorType::Raise(expr.clone())
                )]
            }
        })
    }
}


impl TranslationMemory for SymbolicEngine {
    fn get_u8(&self, address: u64) -> Option<u8> {
        self.load_only_concrete(address).unwrap()
    }
}



/// Return true if an expression is all constants.
///
/// If an expression is all constants, we can evaluate the expression
/// concretely and return its constant value).
pub fn all_constants(expr: &il::Expression) -> bool {
    match *expr {
        il::Expression::Scalar(_) => false,
        il::Expression::Constant(_) => true,
        il::Expression::Add(ref lhs, ref rhs) |
        il::Expression::Sub(ref lhs, ref rhs) |
        il::Expression::Mul(ref lhs, ref rhs) |
        il::Expression::Divu(ref lhs, ref rhs) |
        il::Expression::Modu(ref lhs, ref rhs) |
        il::Expression::Divs(ref lhs, ref rhs) |
        il::Expression::Mods(ref lhs, ref rhs) |
        il::Expression::And(ref lhs, ref rhs) |
        il::Expression::Or(ref lhs, ref rhs) |
        il::Expression::Xor(ref lhs, ref rhs) |
        il::Expression::Shl(ref lhs, ref rhs) |
        il::Expression::Shr(ref lhs, ref rhs) | 
        il::Expression::Cmpeq(ref lhs, ref rhs) |
        il::Expression::Cmpneq(ref lhs, ref rhs) |
        il::Expression::Cmplts(ref lhs, ref rhs) |
        il::Expression::Cmpltu(ref lhs, ref rhs) =>
            all_constants(lhs) && all_constants(rhs),
        il::Expression::Zext(_, ref src) |
        il::Expression::Sext(_, ref src) |
        il::Expression::Trun(_, ref src) =>
            all_constants(src)
    }
}


pub fn simplify_or(expr: &il::Expression) -> Result<il::Expression> {

    fn associate_left(lhs: il::Expression, rhs: il::Expression) -> Result<il::Expression> {
        match (lhs, rhs) {
            (il::Expression::Or(lhs_, rhs_), il::Expression::Constant(rhs_c)) => {
                if let il::Expression::Constant(_) = *lhs_ {
                    il::Expression::or(
                        executor::constants_expression(&il::Expression::or(*lhs_, rhs_c.into())?)?.into(),
                        *rhs_
                    )
                }
                else if let il::Expression::Constant(_) = *rhs_ {
                    il::Expression::or(
                        executor::constants_expression(&il::Expression::or(*rhs_, rhs_c.into())?)?.into(),
                        *lhs_
                    )
                }
                else {
                    il::Expression::or(il::Expression::or(*lhs_, *rhs_)?, rhs_c.into())
                }
            },
            (lhs, rhs) => il::Expression::or(lhs, rhs)
        }
    }

    fn associate_right(lhs: il::Expression, rhs: il::Expression) -> Result<il::Expression> {
        match (lhs, rhs) {
            (il::Expression::Constant(lhs_c), il::Expression::Or(lhs_, rhs_)) => {
                if let il::Expression::Constant(_) = *lhs_ {
                    il::Expression::or(
                        executor::constants_expression(&il::Expression::or(*lhs_, lhs_c.into())?)?.into(),
                        *rhs_
                    )
                }
                else if let il::Expression::Constant(_) = *rhs_ {
                    il::Expression::or(
                        executor::constants_expression(&il::Expression::or(*rhs_, lhs_c.into())?)?.into(),
                        *lhs_
                    )
                }
                else {
                    il::Expression::or(il::Expression::or(*lhs_, *rhs_)?, lhs_c.into())
                }
            },
            (lhs, rhs) => il::Expression::or(lhs, rhs)
        }
    }


    if let il::Expression::Or(ref lhs, ref rhs) = *expr {
        let lhs = simplify_expression(lhs)?;
        let rhs = simplify_expression(rhs)?;

        if let il::Expression::Constant(_) = lhs {
            if let il::Expression::Constant(_) = rhs {
                return Ok(executor::constants_expression(&il::Expression::or(lhs, rhs)?)?.into());
            }
        }

        if let il::Expression::Or(lhs, rhs) = associate_left(lhs, rhs)? {
            return associate_right(*lhs, *rhs)
        }
        else {
            bail!("simplify_or associate_left didn't return il::Expression::Or")
        }
    }
    else {
        bail!("Non-or expression passed to simplify_or")
    }
}


/// Fold all constant expressions, leaving the bare minimum expression needed
/// to evaluate over scalars.
pub fn simplify_expression(expr: &il::Expression) -> Result<il::Expression> {
    Ok(match *expr {
        il::Expression::Constant(ref c) => c.clone().into(),
        il::Expression::Scalar(ref s) => s.clone().into(),
        // Handle Or separately for now, greatly simplifying memory loads/store expressions
        il::Expression::Or(_, _) => simplify_or(expr)?,
        il::Expression::Add(ref lhs, ref rhs) |
        il::Expression::Sub(ref lhs, ref rhs) |
        il::Expression::Mul(ref lhs, ref rhs) |
        il::Expression::Divu(ref lhs, ref rhs) |
        il::Expression::Modu(ref lhs, ref rhs) |
        il::Expression::Divs(ref lhs, ref rhs) |
        il::Expression::Mods(ref lhs, ref rhs) | 
        il::Expression::And(ref lhs, ref rhs) |
        il::Expression::Xor(ref lhs, ref rhs) |
        il::Expression::Shl(ref lhs, ref rhs) |
        il::Expression::Shr(ref lhs, ref rhs) |
        il::Expression::Cmpeq(ref lhs, ref rhs) |
        il::Expression::Cmpneq(ref lhs, ref rhs) |
        il::Expression::Cmplts(ref lhs, ref rhs) |
        il::Expression::Cmpltu(ref lhs, ref rhs) => {
            let lhs = simplify_expression(lhs)?;
            let rhs = simplify_expression(rhs)?;
            if let il::Expression::Constant(_) = lhs {
                if let il::Expression::Constant(_) = rhs {
                    return Ok(match *expr {
                        il::Expression::Add(_, _) => 
                            executor::constants_expression(&il::Expression::add(lhs, rhs)?)?.into(),                        
                        il::Expression::Sub(_, _) => 
                            executor::constants_expression(&il::Expression::sub(lhs, rhs)?)?.into(),
                        il::Expression::Mul(_, _) => 
                            executor::constants_expression(&il::Expression::mul(lhs, rhs)?)?.into(),
                        il::Expression::Divu(_, _) => 
                            executor::constants_expression(&il::Expression::divu(lhs, rhs)?)?.into(),
                        il::Expression::Modu(_, _) => 
                            executor::constants_expression(&il::Expression::modu(lhs, rhs)?)?.into(),
                        il::Expression::Divs(_, _) => 
                            executor::constants_expression(&il::Expression::divs(lhs, rhs)?)?.into(),
                        il::Expression::Mods(_, _) => 
                            executor::constants_expression(&il::Expression::mods(lhs, rhs)?)?.into(),
                        il::Expression::And(_, _) => 
                            executor::constants_expression(&il::Expression::and(lhs, rhs)?)?.into(),
                        il::Expression::Xor(_, _) => 
                            executor::constants_expression(&il::Expression::xor(lhs, rhs)?)?.into(),
                        il::Expression::Shl(_, _) => 
                            executor::constants_expression(&il::Expression::shl(lhs, rhs)?)?.into(),
                        il::Expression::Shr(_, _) => 
                            executor::constants_expression(&il::Expression::shr(lhs, rhs)?)?.into(),
                        il::Expression::Cmpeq(_, _) => 
                            executor::constants_expression(&il::Expression::cmpeq(lhs, rhs)?)?.into(),
                        il::Expression::Cmpneq(_, _) => 
                            executor::constants_expression(&il::Expression::cmpneq(lhs, rhs)?)?.into(),
                        il::Expression::Cmplts(_, _) => 
                            executor::constants_expression(&il::Expression::cmplts(lhs, rhs)?)?.into(),
                        il::Expression::Cmpltu(_, _) => 
                            executor::constants_expression(&il::Expression::cmpltu(lhs, rhs)?)?.into(),
                        _ => bail!("Unreachable in simplify_expression")
                    }) // return match expr
                } // if let il::Expression::Constant(rhs) = rhs
            } // if let il::Expression::Constant(lhs) = lhs
            match *expr {
                il::Expression::Add(_, _) => il::Expression::add(lhs, rhs)?,
                il::Expression::Sub(_, _) => il::Expression::sub(lhs, rhs)?,
                il::Expression::Mul(_, _) => il::Expression::mul(lhs, rhs)?,
                il::Expression::Divu(_, _) => il::Expression::divu(lhs, rhs)?,
                il::Expression::Modu(_, _) => il::Expression::modu(lhs, rhs)?,
                il::Expression::Divs(_, _) => il::Expression::divs(lhs, rhs)?,
                il::Expression::Mods(_, _) => il::Expression::mods(lhs, rhs)?,
                il::Expression::And(_, _) => il::Expression::and(lhs, rhs)?,
                il::Expression::Xor(_, _) => il::Expression::xor(lhs, rhs)?,
                il::Expression::Shl(_, _) => il::Expression::shl(lhs, rhs)?,
                il::Expression::Shr(_, _) => il::Expression::shr(lhs, rhs)?,
                il::Expression::Cmpeq(_, _) => il::Expression::cmpeq(lhs, rhs)?,
                il::Expression::Cmpneq(_, _) => il::Expression::cmpneq(lhs, rhs)?,
                il::Expression::Cmplts(_, _) => il::Expression::cmplts(lhs, rhs)?,
                il::Expression::Cmpltu(_, _) => il::Expression::cmpltu(lhs, rhs)?,
                _ => bail!("Unreachable in simplify_expression")
            } // match expr
        },
        il::Expression::Zext(bits, ref rhs) |
        il::Expression::Sext(bits, ref rhs) |
        il::Expression::Trun(bits, ref rhs) => {
            let rhs = simplify_expression(rhs)?;
            if let il::Expression::Constant(_) = rhs {
                match *expr {
                    il::Expression::Zext(_, _) =>
                        executor::constants_expression(&il::Expression::zext(bits, rhs)?)?.into(),
                    il::Expression::Sext(_, _) =>
                        executor::constants_expression(&il::Expression::sext(bits, rhs)?)?.into(),
                    il::Expression::Trun(_, _) =>
                        executor::constants_expression(&il::Expression::trun(bits, rhs)?)?.into(),
                    _ => bail!("Unreachable in simplify_expression")
                }
            }
            else {
                match *expr {
                    il::Expression::Zext(bits, ref rhs) => il::Expression::zext(bits, simplify_expression(rhs)?)?,
                    il::Expression::Sext(bits, ref rhs) => il::Expression::sext(bits, simplify_expression(rhs)?)?,
                    il::Expression::Trun(bits, ref rhs) => il::Expression::trun(bits, simplify_expression(rhs)?)?,
                    _ => bail!("Unreachable in simplify_expression")
                }
            }
        }
    })// match expr
}


/// Convert a falcon expression to its `smtlib2` equivalent.
pub fn expr_to_smtlib2(expr: &il::Expression) -> String {
    match *expr {
        il::Expression::Constant(ref c) => {
            if c.bits() == 1 {
                format!("#b{}", c.value())
            }
            else {
                format!("#x{:01$x}", c.value(), c.bits() / 4)
            }
        },
        il::Expression::Scalar(ref s) => {
            s.name().to_string()
        }
        il::Expression::Add ( ref lhs, ref rhs ) =>
            format!("(bvadd {} {})", expr_to_smtlib2(lhs), expr_to_smtlib2(rhs)),
        il::Expression::Sub ( ref lhs, ref rhs ) =>
            format!("(bvsub {} {})", expr_to_smtlib2(lhs), expr_to_smtlib2(rhs)),
        il::Expression::Mul ( ref lhs, ref rhs ) =>
            format!("(bvmul {} {})", expr_to_smtlib2(lhs), expr_to_smtlib2(rhs)),
        il::Expression::Divu ( ref lhs, ref rhs ) =>
            format!("(bvudiv {} {})", expr_to_smtlib2(lhs), expr_to_smtlib2(rhs)),
        il::Expression::Modu ( ref lhs, ref rhs ) =>
            format!("(bvumod {} {})", expr_to_smtlib2(lhs), expr_to_smtlib2(rhs)),
        il::Expression::Divs ( ref lhs, ref rhs ) =>
            format!("(bvsdiv {} {})", expr_to_smtlib2(lhs), expr_to_smtlib2(rhs)),
        il::Expression::Mods ( ref lhs, ref rhs ) =>
            format!("(bvsmod {} {})", expr_to_smtlib2(lhs), expr_to_smtlib2(rhs)),
        il::Expression::And ( ref lhs, ref rhs ) =>
            format!("(bvand {} {})", expr_to_smtlib2(lhs), expr_to_smtlib2(rhs)),
        il::Expression::Or ( ref lhs, ref rhs ) =>
            format!("(bvor {} {})", expr_to_smtlib2(lhs), expr_to_smtlib2(rhs)),
        il::Expression::Xor ( ref lhs, ref rhs ) =>
            format!("(bvxor {} {})", expr_to_smtlib2(lhs), expr_to_smtlib2(rhs)),
        il::Expression::Shl ( ref lhs, ref rhs ) =>
            format!("(bvshl {} {})", expr_to_smtlib2(lhs), expr_to_smtlib2(rhs)),
        il::Expression::Shr ( ref lhs, ref rhs ) =>
            format!("(bvlshr {} {})", expr_to_smtlib2(lhs), expr_to_smtlib2(rhs)),
        il::Expression::Cmpeq ( ref lhs, ref rhs ) =>
            format!("(ite (= {} {}) #b1 #b0)",
                    expr_to_smtlib2(lhs),
                    expr_to_smtlib2(rhs)),
        il::Expression::Cmpneq ( ref lhs, ref rhs ) =>
            format!("(ite (!= {} {}) #b1 #b0)",
                    expr_to_smtlib2(lhs),
                    expr_to_smtlib2(rhs)),
        il::Expression::Cmplts ( ref lhs, ref rhs ) =>
            format!("(ite (bvslt {} {}) #b1 #b0)",
                    expr_to_smtlib2(lhs),
                    expr_to_smtlib2(rhs)),
        il::Expression::Cmpltu ( ref lhs, ref rhs ) =>
            format!("(ite (bvult {} {}) #b1 #b0)",
                    expr_to_smtlib2(lhs),
                    expr_to_smtlib2(rhs)),
        il::Expression::Zext ( bits, ref rhs ) =>
            format!("(concat (_ bv0 {}) {})",
                    bits - rhs.bits(),
                    expr_to_smtlib2(rhs)),
        il::Expression::Sext ( bits, ref rhs ) =>
            format!("((_ sign_extend {}) {})",
                    bits - rhs.bits(),
                    expr_to_smtlib2(rhs)),
        il::Expression::Trun ( bits, ref rhs ) =>
            format!("((_ extract {} 0) {})", bits - 1, expr_to_smtlib2(rhs))
    }
}