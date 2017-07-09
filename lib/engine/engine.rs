use error::*;
use executor;
use il;
use il::variable::Variable;
use std::collections::{BTreeMap, BTreeSet};
use engine::memory::SymbolicMemory;
use engine::platform::Platform;


#[derive(Clone)]
pub enum SuccessorType {
    FallThrough,
    Branch(u64)
}


#[derive(Clone)]
pub struct SymbolicSuccessor {
    successor_type: SuccessorType,
    engine: SymbolicEngine
}


impl SymbolicSuccessor {
    pub fn new(engine: SymbolicEngine, successor_type: SuccessorType)
        -> SymbolicSuccessor {

        SymbolicSuccessor {
            engine: engine,
            successor_type: successor_type
        }
    }


    pub fn successor_type(&self) -> &SuccessorType {
        &self.successor_type
    }


    pub fn into_engine(self) -> SymbolicEngine {
        self.engine
    }
}


#[derive(Clone)]
pub struct SymbolicEngine {
    scalars: BTreeMap<String, il::Expression>,
    memory: SymbolicMemory,
    assertions: Vec<il::Expression>
}


impl SymbolicEngine {
    pub fn new(memory: SymbolicMemory) -> SymbolicEngine {
        SymbolicEngine {
            scalars: BTreeMap::new(),
            memory: memory,
            assertions: Vec::new(),
        }
    }


    pub fn add_assertion(&mut self, assertion: il::Expression) {
        self.assertions.push(assertion);
    }


    /// Set a symbolic scalar
    pub fn set_scalar<S>(&mut self, name: S, value: il::Expression)
        where S: Into<String> {
        self.scalars.insert(name.into(), value);
    }


    /// Get the value of a symbolic value according to current state
    pub fn get_scalar(&self, name: &str) -> Option<&il::Expression> {
        self.scalars.get(name)
    }


    /// Replace scalars in the expression with those in the engine's current
    /// scalar to expression mapping, and if all scalars are currently constant,
    /// evaluate to constant and return that. Otherwise, return expression with
    /// symbolic values
    pub fn symbolize_and_eval(&self, expression: il::Expression)
        -> Result<il::Expression> {

        let expression = self.symbolize_expression(&expression)?;
        if all_constants(&expression) {
            let constant = executor::constants_expression(&expression)?;
            Ok(il::Expression::Constant(constant))
        }
        else {
            Ok(expression)
        }
    }

    /// Replaces scalars in the expression with those in the engine's current
    /// scalar to expression mapping, and then evaluates for a concrete value
    /// TODO: You know, concretization given a solver...
    pub fn symbolize_and_concretize(&self, expression: il::Expression)
        -> il::Constant {

        panic!("Unimplemented");
    }


    /// Forks the state of the symbolic engine
    pub fn fork(&self) -> SymbolicEngine {
        SymbolicEngine {
            scalars: self.scalars.clone(),
            memory: self.memory.clone(),
            assertions: self.assertions.clone()
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
            il::Expression::Constant(ref constant) => expression.clone(),
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


    pub fn eval(&self, expr: &il::Expression) -> Option<u64> {
        let mut solver_lines : Vec<String> = Vec::new();
        solver_lines.push("(set-option :produce-models true)".to_string());
        solver_lines.push("(set-logic QF_AFBV)".to_string());
        solver_lines.push("(set-info :smt-lib-version 2.0)".to_string());

        // Collect all the scalars from our assertions
        let mut assertion_scalars: BTreeSet<(String, usize)> = BTreeSet::new();
        for assertion in &self.assertions {
            for scalar in assertion.collect_scalars() {
                assertion_scalars.insert(
                    (scalar.name().to_string(), scalar.bits())
                );
            }
        }

        // Add in scalars from our expression
        for scalar in expr.collect_scalars() {
            assertion_scalars.insert(
                (scalar.name().to_string(), scalar.bits())
            );
        }

        for assertion_scalar in &assertion_scalars {
            solver_lines.push(format!("(declare-fun {} () (_ BitVec {}))",
                assertion_scalar.0, assertion_scalar.1));
        }

        // Assert our assertions
        for assertion in &self.assertions {
            solver_lines.push(format!("(assert (= #b1 {}))",
                expr_to_smtlib2(&assertion)));
        }

        println!("{}", solver_lines.join("\n"));

        None
    }


    /// Execute an IL operation over the engine, updating state.
    pub fn execute(mut self, operation: &il::Operation)
        -> Result<Vec<SymbolicSuccessor>> {

        Ok(match *operation {
            il::Operation::Assign { ref dst, ref src } => {
                let src = self.symbolize_and_eval(src.clone())?;
                self.scalars.insert(dst.name().to_string(), src);
                vec![SymbolicSuccessor::new(self, SuccessorType::FallThrough)]
            },
            il::Operation::Store { ref dst, ref index, ref src } => {
                let src = self.symbolize_and_eval(src.clone())?;
                let index = self.symbolize_and_concretize(index.clone());
                self.memory.store(index.value(), src)?;
                vec![SymbolicSuccessor::new(self, SuccessorType::FallThrough)]
            },
            il::Operation::Load { ref dst, ref index, ref src } => {
                let index = self.symbolize_and_concretize(index.clone());
                let value = self.memory.load(index.value(), dst.bits())?;
                match value {
                    Some(v) => {
                        self.scalars.insert(dst.name().to_string(), v.clone());
                        vec![SymbolicSuccessor::new(self, SuccessorType::FallThrough)]
                    },
                    None => Vec::new()
                }
            },
            il::Operation::Brc { ref target, ref condition } => {
                let mut successors = Vec::new();
                if self.eval(condition) == None {
                    let engine = self.fork();
                    let successor = SymbolicSuccessor::new(
                        engine,
                        SuccessorType::FallThrough
                    );
                    successors.push(successor);
                }
                if let Some(r) = self.eval(condition) {
                    if let Some(target) = self.eval(target) {
                        let mut engine = self.fork();
                        engine.add_assertion(condition.clone());
                        let successor = SymbolicSuccessor::new(
                            engine,
                            SuccessorType::Branch(target)
                        );
                        successors.push(successor);
                    }
                }
                successors
            },
            il::Operation::Phi { ref dst, ref src } => {
                vec![SymbolicSuccessor::new(self, SuccessorType::FallThrough)]
            },
            il::Operation::Raise { ref expr } => {
                panic!("raise unimplemented")
            }
        })
    }
}


/// Return true if an expression is all constants (and we can therefor evaluate
/// the expression concretely and return its constant value).
fn all_constants(expr: &il::Expression) -> bool {
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
            all_constants(lhs) || all_constants(rhs),
        il::Expression::Zext(_, ref src) |
        il::Expression::Sext(_, ref src) |
        il::Expression::Trun(_, ref src) =>
            all_constants(src)
    }
}


fn scalar_to_smtlib2(s: &il::Scalar) -> String {
    format!("{}_ssa{}", s.name(), match s.ssa() {
        Some(s) => format!("{}", s),
        None => "".to_string()
    })
}


fn expr_to_smtlib2(expr: &il::Expression) -> String {
    match *expr {
        il::Expression::Constant(ref c) => {
            if c.bits() == 1 {
                format!("#b{}", c.value())
            }
            else {
                format!("#x{:0x}", c.value())
            }
        },
        il::Expression::Scalar(ref s) => {
            scalar_to_smtlib2(s)
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
            format!("(bvshr {} {})", expr_to_smtlib2(lhs), expr_to_smtlib2(rhs)),
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
            format!("(concat (_ bv0 {}) {}",
                    bits - rhs.bits(),
                    expr_to_smtlib2(rhs)),
        il::Expression::Sext ( bits, ref rhs ) =>
            format!("((_ sign_extend {}) {})",
                    bits - rhs.bits(),
                    expr_to_smtlib2(rhs)),
        il::Expression::Trun ( bits, ref rhs ) =>
            format!("((_ extract {} 0) {})", bits, expr_to_smtlib2(rhs))
    }
}