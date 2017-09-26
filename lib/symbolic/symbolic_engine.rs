use il;
use symbolic::*;
use error::*;
use executor;
use std::collections::BTreeMap;
use std::rc::Rc;
use translator::TranslationMemory;

/// An engine for maintaining a symbolic state, performing operations over that
/// state, and querying that state.
#[derive(Clone, Deserialize, Serialize)]
pub struct SymbolicEngine {
    scalars: BTreeMap<String, il::Expression>,
    memory: SymbolicMemory,
    constraints: Vec<il::Expression>,
    #[serde(skip)]
    solver: Rc<Solver>
}


impl SymbolicEngine {
    /// Create a new `SymbolicEngine`
    pub fn new(memory: SymbolicMemory) -> SymbolicEngine {
        SymbolicEngine {
            scalars: BTreeMap::new(),
            memory: memory,
            constraints: Vec::new(),
            solver: Rc::new(Solver::new().unwrap())
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
        &mut self,
        expr: &il::Expression,
        constraints: Option<Vec<il::Expression>>
    ) -> Result<Option<il::Constant>> {

        // Create one vec of constraints
        let constraints = match constraints {
            Some(constraints) => {
                let mut c = Vec::new();
                for constraint in constraints {
                    let constraint = self.symbolize_expression(&constraint)?;
                    if all_constants(&constraint) {
                        if executor::constants_expression(&constraint)?.value() == 0 {
                            return Ok(None)
                        }
                    }
                    else {
                        c.push(constraint);
                    }
                }
                c.append(&mut self.constraints.clone());
                c
            },
            None => self.constraints.clone()
        };

        let expr = self.symbolize_expression(expr)?;

        if all_constants(&expr) {
            return Ok(Some(executor::constants_expression(&expr)?));
        }

        Rc::make_mut(&mut self.solver).solve(&expr, constraints)
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
    pub fn sat(&mut self, constraints: Option<Vec<il::Expression>>) -> Result<bool> {
        // An expression that will always evaluate to true
        let expression = il::Expression::cmpeq(
            il::expr_scalar("dummy_sat_variable", 1),
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
                let index = self.eval(index, None)?;
                if let Some(index) = index {
                    self.memory.store(index.value(), src)?;
                    vec![SymbolicSuccessor::new(self, SuccessorType::FallThrough)]
                }
                else {
                    Vec::new()
                }
            },
            il::Operation::Load { ref dst, ref index, .. } => {
                let index_ = self.eval(index, None)?;
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
                let r = self.eval(&null_case, Some(vec![null_case.clone()]))?;
                if r.is_some() {
                    let mut engine = self.clone();
                    engine.add_constraint(null_case)?;
                    let successor = SymbolicSuccessor::new(engine, SuccessorType::FallThrough);
                    successors.push(successor);
                }
                // This is the true case
                let r = self.eval(&condition, Some(vec![condition.clone()]))?;
                if r.is_some() {
                    let t = self.eval(target, Some(vec![condition.clone()]))?;
                    if let Some(target) = t {
                        let mut engine = self.clone();
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