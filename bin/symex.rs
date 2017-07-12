use error::*;
use falcon::engine::*;
use falcon::il;
use falcon::loader::Loader;
use std::collections::VecDeque;
use std::path::Path;


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


// A unique location in a function
#[derive(Clone, Debug)]
pub enum FunctionLocation {
    Instruction {
        block_index: u64,
        instruction_index: u64,
    },
    Edge {
        head: u64,
        tail: u64
    }
}


// A unique location in a program
#[derive(Clone, Debug)]
pub struct ProgramLocation {
    function_index: u64,
    function_location: FunctionLocation
}

impl ProgramLocation {
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
    /// TODO: Handle cases where the address is invalid
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
    /// want to advance past all of these things to the next valid instruction.
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


#[derive(Clone)]
pub struct EngineDriver<'e> {
    program: &'e il::Program,
    location: ProgramLocation,
    engine: SymbolicEngine
}





/// An EngineDriver drive's a symbolic engine through a program
impl<'e> EngineDriver<'e> {
    pub fn new(
        program: &'e il::Program,
        location: ProgramLocation,
        engine: SymbolicEngine
    ) -> EngineDriver<'e> {

        EngineDriver {
            program: program,
            location: location,
            engine: engine
        }
    }

    /// Steps this engine forward, consuming the engine and returning some
    /// variable number of EngineDriver back depending on how many possible
    /// states are possible.
    pub fn step(mut self) -> Result<Vec<EngineDriver<'e>>> {
        let mut new_engine_drivers = Vec::new();
        match self.location.function_location {
            FunctionLocation::Instruction { block_index, instruction_index } => {
                let instruction = self.program
                                      .function(self.location.function_index())
                                      .unwrap()
                                      .block(block_index)
                                      .unwrap()
                                      .instruction(instruction_index)
                                      .unwrap();

                let successors = self.engine.execute(instruction.operation())?;

                for successor in successors {
                    match *successor.type_() {
                        SuccessorType::FallThrough => {
                            // Get the possible successor locations for the current
                            // location
                            let engine = successor.into_engine();
                            for location in self.location.advance(self.program) {
                                new_engine_drivers.push(EngineDriver::new(
                                    self.program,
                                    location,
                                    engine.clone()
                                ));
                            }
                        },
                        SuccessorType::Branch(address) => {
                            let location = ProgramLocation::from_address(address, self.program)
                                .unwrap();
                            new_engine_drivers.push(EngineDriver::new(
                                self.program,
                                location,
                                successor.into_engine()
                            ));
                        }
                    }
                } 
            },
            FunctionLocation::Edge { head, tail } => {
                let mut new_engine_drivers = Vec::new();
                let edge = self.location
                               .function(self.program)
                               .unwrap()
                               .edge(head, tail)
                               .unwrap();
                match *edge.condition() {
                    None => {
                        if edge.condition().is_none() {
                            for location in self.location.advance(self.program) {
                                new_engine_drivers.push(EngineDriver::new(
                                    self.program,
                                    location,
                                    self.engine.clone()
                                ));
                            }
                        }
                    },
                    Some(ref condition) => {
                        self.engine.add_assertion(condition.clone());
                        if self.engine.sat(None)? {
                            for location in self.location.advance(self.program) {
                                new_engine_drivers.push(EngineDriver::new(
                                    self.program,
                                    location,
                                    self.engine.clone()
                                ));
                            }
                        }
                    }
                }
            }
        } // match self.location.function_location
        Ok(new_engine_drivers)
    }

    /// Return the program for this driver
    pub fn program(&self) -> &il::Program {
        self.program
    }

    /// Return the location of this driver
    pub fn location(&self) -> &ProgramLocation {
        &self.location
    }

    /// Set the location for this driver.
    pub fn set_location(&mut self, location: ProgramLocation) {
        self.location = location;
    }

    /// Return the underlying symbolic engine for this driver
    pub fn engine(&self) -> &SymbolicEngine {
        &self.engine
    }
}


pub fn engine_test () -> Result<()> {
    let filename = Path::new("test_binaries/Palindrome/Palindrome.json");
    let elf = ::falcon::loader::json::Json::from_file(filename)?;

    let program = elf.to_program()?;

    println!("{}", program);

    // Initialize memory.
    let mut memory = SymbolicMemory::new(32, ::falcon::engine::Endian::Little);

    // Load all memory as given by the loader.
    for (address, segment) in elf.memory()?.segments() {
        let bytes = segment.bytes();
        for i in 0..bytes.len() {
            memory.store(*address + i as u64, il::expr_const(bytes[i] as u64, 8))?;
        }
    }

    // Set up space for the stack.
    let stack_address : u64 = 0xb0000000;
    let stack_size : u64 = 0x10000;
    let initial_stack_pointer : u64 = 0xb0000000 - 0x1000;

    for i in 0..stack_size {
        memory.store(stack_address - stack_size + i, il::expr_const(0, 8))?;
    }

    // Create the engine
    let mut engine = SymbolicEngine::new(memory);

    // Set our initial variables
    engine.set_scalar("esp", il::expr_const(initial_stack_pointer, 32));
    engine.set_scalar("DF", il::expr_const(0, 1));

    // Get the first instruction we care about
    let ia = instruction_address(&program, 0x804880f).unwrap();

    // Find the instruction
    let function = program.function(ia.0).unwrap();
    let control_flow_graph = function.control_flow_graph();

    // Let's execute everything in the first block
    for instruction in control_flow_graph.block(ia.1).unwrap().instructions() {
        println!("Executing {}", instruction);
        let mut successors = engine.execute(instruction.operation())?;
        if successors.is_empty() {
            panic!("No successors");
        }
        if successors.len() > 1 {
            panic!("More than one successor");
        }
        let successor = successors.remove(0);
        engine = match *successor.type_() {
            SuccessorType::FallThrough => successor.into_engine(),
            SuccessorType::Branch(address) =>
                panic!("SuccessorType::Branch {}", address)
        };
    }

    Ok(())
}

