//! An `EngineDriver` drives multiple `SymbolicEngine`s, taking care of control flow from an
//! `il::Program` and handling `Platform`-specific actions.
//!
//! An `EngineDriver` performs the following actions:
//!   * Keeps track of our current location in an `il::Program`.
//!   * Handles `SymbolicSuccessor` results from a `SymbolicEngine`.
//!   * Translates/lifts code using a `translator::Arch` with `SymbolicMemory` as the
//!     `TranslationMemory` backing when we encounter branch targets we have not yet translated.
//!
//! An `EngineDriver` is the core component of symbolic execution with Falcon, whereas a
//! `SymbolicEngine` is the core component of an `EngineDriver`. `EngineDriver`, "Drives," a
//! `SymbolicEngine`.

use error::*;
use symbolic::*;
use il;
use platform::Platform;
use translator;
use std::rc::Rc;



/// An `EngineDriver` drive's a `SymbolicEngine` through an `il::Program` and `Platform`.
#[derive(Clone)]
pub struct SymbolicDriver<'e, P> {
    program: Rc<il::Program>,
    location: il::ProgramLocation,
    engine: SymbolicEngine,
    arch: &'e Box<translator::Arch>,
    platform: Rc<P>
}



impl<'e, P> SymbolicDriver<'e, P> {
    /// Create a new `EngineDriver`.
    ///
    /// # Arguments
    /// * `program`: An `il::Program`. Must not be complete, but must have the location pointed to by
    /// _location_ validly translated.
    /// * `location`: A valid location in _program_, which is the next instruction to execute.
    /// * `engine`: The `SymbolicEngine` holding the state of the program at this point in time.
    /// * `arch`: A `translator::Arch` for this program's architecture. This will be used to
    /// translate unexplored program blocks on the fly.
    /// * `platform`: The platform we will use to handle `Raise` instructions. `Platform` models the
    /// external environment and may be stateful.
    pub fn new(
        program: Rc<il::Program>,
        location: il::ProgramLocation,
        engine: SymbolicEngine,
        arch: &'e Box<translator::Arch>,
        platform: Rc<P>
    ) -> SymbolicDriver<P> where P: Platform<P> {

        SymbolicDriver {
            program: program,
            location: location,
            engine: engine,
            arch: arch,
            platform: platform
        }
    }


    /// Steps this engine forward, consuming the engine and returning some
    /// variable number of `EngineDriver` back depending on how many possible
    /// states are possible.
    pub fn step(mut self) -> Result<Vec<SymbolicDriver<'e, P>>> where P: Platform<P> {
        let mut new_engine_drivers = Vec::new();
        let location = self.location.apply(&self.program).unwrap();
        match *location.function_location() {
            il::RefFunctionLocation::Instruction(_, instruction) => {
                let successors = {
                    // println!("Executing instruction {}", instruction);
                    match *instruction.operation() {
                        il::Operation::Load { ref index, .. } => {
                            let expr = self.engine.symbolize_expression(index)?;
                            if !all_constants(&expr) {
                                println!("Loading from non-constant address");
                                if let Some(address) = self.address() {
                                    println!("address: 0x{:x}", address);
                                }
                            }
                        },
                        _ => {}
                    }
                    self.engine.execute(instruction.operation())?
                };

                for successor in successors {
                    match successor.type_().clone() {
                        SuccessorType::FallThrough => {
                            // Get the possible successor locations for the current
                            // location
                            let engine = successor.into_engine();
                            let locations = location.advance_forward()?;
                            if locations.len() == 1 {
                                new_engine_drivers.push(SymbolicDriver::new(
                                    self.program.clone(),
                                    locations[0].clone().into(),
                                    engine,
                                    self.arch,
                                    self.platform.clone(),
                                ));
                            }
                            else {
                                for location in locations {
                                    new_engine_drivers.push(SymbolicDriver::new(
                                        self.program.clone(),
                                        location.into(),
                                        engine.clone(),
                                        self.arch,
                                        self.platform.clone()
                                    ));
                                }
                            }
                        },
                        SuccessorType::Branch(address) => {
                            match il::RefProgramLocation::from_address(&self.program, address) {
                                // We have already disassembled the branch target. Go straight to it.
                                Some(location) => new_engine_drivers.push(SymbolicDriver::new(
                                    self.program.clone(),
                                    location.into(),
                                    successor.into_engine(),
                                    self.arch,
                                    self.platform.clone()
                                )),
                                // There's no instruction at this address. We will attempt
                                // disassembling a function here.
                                None => {
                                    let engine = successor.into_engine();
                                    let function = self.arch.translate_function(&engine, address);
                                    match function {
                                        Ok(function) => {
                                            let mut program = self.program.clone();
                                            Rc::make_mut(&mut program).add_function(function);
                                            let location = il::RefProgramLocation::from_address(
                                                &program,
                                                address
                                            );
                                            if let Some(location) = location {
                                                new_engine_drivers.push(SymbolicDriver::new(
                                                    program.clone(),
                                                    location.into(),
                                                    engine,
                                                    self.arch,
                                                    self.platform.clone()
                                                ));
                                            }
                                            else {
                                                bail!("No instruction at address 0x{:x}", address)
                                            }
                                        },
                                        Err(_) => bail!("Failed to lift function at address 0x{:x}", address)
                                    }
                                }
                            };
                        },
                        SuccessorType::Raise(expression) => {
                            let platform = Rc::make_mut(&mut self.platform).to_owned();
                            let locations = location.advance_forward()?;
                            let engine = successor.clone().into_engine();
                            let results = match platform.raise(&expression, engine) {
                                Ok(results) => results,
                                Err(e) => {
                                    println!("Killing state because {}", e.description());
                                    continue;
                                }
                            };
                            for location in locations {
                                for result in &results {
                                    new_engine_drivers.push(SymbolicDriver::new(
                                        self.program.clone(),
                                        location.clone().into(),
                                        result.1.clone(),
                                        self.arch,
                                        Rc::new(result.0.clone())
                                    ));
                                }
                            }
                        }
                    }
                } 
            },
            il::RefFunctionLocation::Edge(edge) => {
                match *edge.condition() {
                    None => {
                        if edge.condition().is_none() {
                            let locations = location.advance_forward()?;
                            if locations.len() == 1 {
                                new_engine_drivers.push(SymbolicDriver::new(
                                    self.program.clone(),
                                    locations[0].clone().into(),
                                    self.engine,
                                    self.arch,
                                    self.platform.clone()
                                ));
                            }
                            else {
                                for location in location.advance_forward()? {
                                    new_engine_drivers.push(SymbolicDriver::new(
                                        self.program.clone(),
                                        location.into(),
                                        self.engine.clone(),
                                        self.arch,
                                        self.platform.clone()
                                    ));
                                }
                            }
                        }
                    },
                    Some(ref condition) => {
                        if self.engine.sat(Some(vec![condition.clone()]))? {
                            let mut engine = self.engine.clone();
                            engine.add_constraint(condition.clone())?;
                            let locations = location.advance_forward()?;
                            if locations.len() == 1 {
                                new_engine_drivers.push(SymbolicDriver::new(
                                    self.program.clone(),
                                    locations[0].clone().into(),
                                    engine,
                                    self.arch,
                                    self.platform.clone()
                                ));
                            }
                            else {
                                for location in location.advance_forward()? {
                                    new_engine_drivers.push(SymbolicDriver::new(
                                        self.program.clone(),
                                        location.into(),
                                        engine.clone(),
                                        self.arch,
                                        self.platform.clone()
                                    ));
                                }
                            }
                        }
                    }
                }
            },
            il::RefFunctionLocation::EmptyBlock(_) => {    
                let locations = location.advance_forward()?;
                for location in locations {
                    new_engine_drivers.push(SymbolicDriver::new(
                        self.program.clone(),
                        location.into(),
                        self.engine.clone(),
                        self.arch,
                        self.platform.clone()
                    ));
                }
            }
        } // match self.location.function_location
        Ok(new_engine_drivers)
    }

    /// If the current location of this EngineDriver is an instruction with an
    /// address, return that address
    pub fn address(&self) -> Option<u64> {
        if let Some(location) = self.location.apply(&self.program) {
            if let Some(instruction) = location.instruction() {
                return instruction.address();
            }
        }
        None
    }

    /// Get the platform for this `EngineDriver`
    pub fn platform(&self) -> Rc<P> {
        self.platform.clone()
    }

    /// Return the program for this `EngineDriver`
    pub fn program(&self) -> &il::Program {
        &self.program
    }

    /// Return the location of this `EngineDriver`
    pub fn location(&self) -> &il::ProgramLocation {
        &self.location
    }

    /// Set the location for this `EngineDriver`.
    pub fn set_location(&mut self, location: il::ProgramLocation) {
        self.location = location;
    }

    /// Return the underlying symbolic engine for this `EngineDriver`
    pub fn engine(&self) -> &SymbolicEngine {
        &self.engine
    }

    /// Return a mutable reference to the engine
    pub fn engine_mut(&mut self) -> &mut SymbolicEngine {
        &mut self.engine
    }
}
