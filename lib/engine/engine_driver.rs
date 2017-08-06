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
use engine::*;
use il;
use platform::Platform;
use translator;
use std::collections::VecDeque;
use std::rc::Rc;

/// Takes a program and an address, and returns function, block, and instruction
/// index for the first IL instruction at that address.
pub fn instruction_address(program: &il::Program, address: u64)
    -> Option<(u64, u64, u64)> {

    for function in program.functions() {
        for block in function.control_flow_graph().blocks() {
            for instruction in block.instructions() {
                if let Some(ins_address) = instruction.address() { 
                    if ins_address == address {
                        return Some(
                            (function.index().unwrap(),
                            block.index(),
                            instruction.index()));
                    }
                }
            }
        }
    }
    None
}


/// A unique location in a function
#[derive(Clone, Debug)]
pub enum FunctionLocation {
    /// A function-unique identifier for an instruction.
    Instruction {
        block_index: u64,
        instruction_index: u64,
    },
    /// A function-unique identifier for an edge.
    Edge {
        head: u64,
        tail: u64
    }
}


/// A unique location in a program
#[derive(Clone, Debug)]
pub struct ProgramLocation {
    function_index: u64,
    function_location: FunctionLocation
}

impl ProgramLocation {
    /// Create a new `ProgramLocation`
    pub fn new(
        function_index: u64,
        function_location: FunctionLocation
    ) -> ProgramLocation {
        ProgramLocation {
            function_index: function_index,
            function_location: function_location
        }
    }


    /// Convert an address to a `ProgramLocation`
    ///
    /// If the address cannot be found, we return `None`.
    pub fn from_address(address: u64, program: &il::Program)
        -> Option<ProgramLocation> {

        for function in program.functions() {
            for block in function.control_flow_graph().blocks() {
                for instruction in block.instructions() {
                    if let Some(ins_address) = instruction.address() {
                        if ins_address == address {
                            return Some(ProgramLocation::new(
                                function.index().unwrap(),
                                FunctionLocation::Instruction {
                                    block_index: block.index(),
                                    instruction_index: instruction.index()
                                }
                            ));
                        }
                    }
                }
            }
        }
        None
    }


    /// Returns the index of this location's function
    pub fn function_index(&self) -> u64 {
        self.function_index
    }


    /// Return the function for this location
    pub fn function<'f>(&self, program: &'f il::Program) -> Option<&'f il::Function> {
        program.function(self.function_index)
    }


    /// Return the FunctionLocation for this location
    pub fn function_location(&self) -> &FunctionLocation {
        &self.function_location
    }


    /// Advances the `DriverLocation` to the next valid `il::Instruction` or
    /// `il::Edge`
    ///
    /// Advancing a location through the program may be tricky due to edge
    /// cases. For example, we may have an unconditional edge leading to an
    /// empty block, leading to another unconditional edge. In this case, we
    /// want to advance past all of these to the next valid `ProgramLocation`.
    pub fn advance(&self, program: &il::Program) -> Vec<ProgramLocation> {
        // This is the list of locations which no longer need to be advanced
        let mut final_locations = Vec::new();

        // This is the queue of locations pending advancement
        let mut queue = VecDeque::new();
        queue.push_back(self.clone());
        while queue.len() > 0 {
            let location = queue.pop_front().unwrap();
            // If we are at an instruction
            match location.function_location {
                FunctionLocation::Instruction { block_index, instruction_index } => {
                    // Iterate through the block to find this instruction
                    let instructions = location.function(program).unwrap()
                                               .block(block_index).unwrap()
                                               .instructions();
                    for i in 0..instructions.len() {
                        // We found this instruction
                        if instructions[i].index() == instruction_index {
                            // If there is a successor in the block, advance to the
                            // successor
                            if i + 1 < instructions.len() {
                                final_locations.push(ProgramLocation::new(
                                    location.function_index,
                                    FunctionLocation::Instruction {
                                        block_index: block_index,
                                        instruction_index: instructions[i + 1].index()
                                    }
                                ));
                                break;
                            }
                            // There is no successor, let's take a look at outgoing
                            // edges
                            for edge in location.function(program)
                                                .unwrap()
                                                .control_flow_graph()
                                                .graph()
                                                .edges_out(block_index)
                                                .unwrap() {
                                // If this is a conditional edge, advance to the
                                // edge
                                if edge.condition().is_some() {
                                    final_locations.push(ProgramLocation::new(
                                        location.function_index,
                                        FunctionLocation::Edge {
                                            head: edge.head(),
                                            tail: edge.tail()
                                        }
                                    ));
                                }
                                // If this is an unconditional edge, push the
                                // unconditional edge onto the queue
                                else {
                                    queue.push_back(ProgramLocation::new(
                                        location.function_index,
                                        FunctionLocation::Edge {
                                            head: edge.head(),
                                            tail: edge.tail()
                                        }
                                    ));
                                }
                            } // for edge
                        } // if instructions[i].index()
                    } // for i in 0..instructions.len()
                },
                FunctionLocation::Edge { head, tail } => {
                    // Get the successor block
                    let block = location.function(program).unwrap()
                                        .block(tail).unwrap();
                    // If this block is empty, we move straight to outgoing
                    // edges
                    if block.instructions().is_empty() {
                        for edge in location.function(program)
                                            .unwrap()
                                            .control_flow_graph()
                                            .graph()
                                            .edges_out(tail)
                                            .unwrap() {
                            // We advance conditional edges, and push
                            // unconditional edges back on the queue
                            // TODO programs with infinite loops, I.E. `while (1) {}`,
                            // will cause us to hang here. We would prefer to hang somewhere else
                            // so we can eventually stop.
                            if edge.condition().is_some() {
                                final_locations.push(ProgramLocation::new(
                                    location.function_index,
                                    FunctionLocation::Edge {
                                        head: edge.head(),
                                        tail: edge.tail()
                                    }
                                ));
                            }
                            else {
                                queue.push_back(ProgramLocation::new(
                                    location.function_index,
                                    FunctionLocation::Edge {
                                        head: edge.head(),
                                        tail: edge.tail()
                                    }
                                ));
                            }
                        } // for edge in location
                    } // if block.instructions().is_empty()
                    // If this block isn't empty, we advance to the first instruction
                    else {
                        final_locations.push(ProgramLocation::new(
                            location.function_index,
                            FunctionLocation::Instruction {
                                block_index: block.index(),
                                instruction_index: block.instructions()[0].index()
                            }
                        ));
                    }
                }
            } // match location
        } // while queue.len() > 0

        final_locations
    }
}


/// An `EngineDriver` drive's a `SymbolicEngine` through an `il::Program` and `Platform`.
#[derive(Clone)]
pub struct EngineDriver<'e, P> {
    program: Rc<il::Program>,
    location: ProgramLocation,
    engine: SymbolicEngine,
    arch: &'e Box<translator::Arch>,
    platform: Rc<P>
}



impl<'e, P> EngineDriver<'e, P> {
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
        location: ProgramLocation,
        engine: SymbolicEngine,
        arch: &'e Box<translator::Arch>,
        platform: Rc<P>
    ) -> EngineDriver<P> where P: Platform<P> {

        EngineDriver {
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
    pub fn step(mut self) -> Result<Vec<EngineDriver<'e, P>>> where P: Platform<P> {
        let mut new_engine_drivers = Vec::new();
        match self.location.function_location {
            FunctionLocation::Instruction { block_index, instruction_index } => {
                let successors = {
                    let instruction = self.program
                                          .function(self.location.function_index())
                                          .unwrap()
                                          .block(block_index)
                                          .unwrap()
                                          .instruction(instruction_index)
                                          .unwrap();

                    // println!("Executing instruction {}", instruction);
                    self.engine.execute(instruction.operation())?
                };

                for successor in successors {
                    match successor.type_().clone() {
                        SuccessorType::FallThrough => {
                            // Get the possible successor locations for the current
                            // location
                            let engine = successor.into_engine();
                            let locations = self.location.advance(&self.program);
                            if locations.len() == 1 {
                                new_engine_drivers.push(EngineDriver::new(
                                    self.program.clone(),
                                    locations[0].clone(),
                                    engine,
                                    self.arch,
                                    self.platform.clone(),
                                ));
                            }
                            else {
                                for location in self.location.advance(&self.program) {
                                    new_engine_drivers.push(EngineDriver::new(
                                        self.program.clone(),
                                        location,
                                        engine.clone(),
                                        self.arch,
                                        self.platform.clone()
                                    ));
                                }
                            }
                        },
                        SuccessorType::Branch(address) => {
                            println!("Branching to 0x{:x}", address);
                            match ProgramLocation::from_address(address, &self.program) {
                                // We have already disassembled the branch target. Go straight to it.
                                Some(location) => new_engine_drivers.push(EngineDriver::new(
                                    self.program.clone(),
                                    location,
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
                                            Rc::make_mut(&mut self.program).add_function(function);
                                            let location = ProgramLocation::from_address(address, &self.program);
                                            if let Some(location) = location {
                                                new_engine_drivers.push(EngineDriver::new(
                                                    self.program.clone(),
                                                    location,
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
                            let locations = self.location.advance(&self.program);
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
                                    new_engine_drivers.push(EngineDriver::new(
                                        self.program.clone(),
                                        location.clone(),
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
            FunctionLocation::Edge { head, tail } => {
                let edge = self.location
                               .function(&self.program)
                               .unwrap()
                               .edge(head, tail)
                               .unwrap();
                match *edge.condition() {
                    None => {
                        if edge.condition().is_none() {
                            for location in self.location.advance(&self.program) {
                                new_engine_drivers.push(EngineDriver::new(
                                    self.program.clone(),
                                    location,
                                    self.engine.clone(),
                                    self.arch,
                                    self.platform.clone()
                                ));
                            }
                        }
                    },
                    Some(ref condition) => {
                        println!("Evaluating condition {}", condition);
                        if self.engine.sat(Some(vec![condition.clone()]))? {
                            println!("Expression sat");
                            let mut engine = self.engine.clone();
                            engine.add_assertion(condition.clone())?;
                            let locations = self.location.advance(&self.program);
                            if locations.len() == 1 {
                                new_engine_drivers.push(EngineDriver::new(
                                    self.program.clone(),
                                    locations[0].clone(),
                                    engine,
                                    self.arch,
                                    self.platform.clone()
                                ));
                            }
                            else {
                                for location in self.location.advance(&self.program) {
                                    new_engine_drivers.push(EngineDriver::new(
                                        self.program.clone(),
                                        location,
                                        engine.clone(),
                                        self.arch,
                                        self.platform.clone()
                                    ));
                                }
                            }
                        }
                    }
                }
            }
        } // match self.location.function_location
        Ok(new_engine_drivers)
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
    pub fn location(&self) -> &ProgramLocation {
        &self.location
    }

    /// Set the location for this `EngineDriver`.
    pub fn set_location(&mut self, location: ProgramLocation) {
        self.location = location;
    }

    /// Return the underlying symbolic engine for this `EngineDriver`
    pub fn engine(&self) -> &SymbolicEngine {
        &self.engine
    }
}
