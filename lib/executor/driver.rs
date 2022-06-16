//! A driver concretely executes a Falcon IL programs.

use crate::architecture::Architecture;
use crate::executor::successor::*;
use crate::executor::State;
use crate::il;
use crate::Error;
use crate::RC;

/// A driver for a concrete executor over Falcon IL.
#[derive(Debug, Clone)]
pub struct Driver {
    program: RC<il::Program>,
    location: il::ProgramLocation,
    state: State,
    architecture: RC<dyn Architecture>,
}

impl Driver {
    /// Create a new driver for concrete execution over Falcon IL.
    pub fn new(
        program: RC<il::Program>,
        location: il::ProgramLocation,
        state: State,
        architecture: RC<dyn Architecture>,
    ) -> Driver {
        Driver {
            program,
            location,
            state,
            architecture,
        }
    }

    /// Step forward over Falcon IL.
    pub fn step(self) -> Result<Driver, Error> {
        let location = self.location.apply(&self.program)?;
        match *location.function_location() {
            il::RefFunctionLocation::Instruction(_, instruction) => {
                let successor = self.state.execute(instruction.operation())?;

                match successor.type_().clone() {
                    SuccessorType::FallThrough => {
                        let locations = location.forward()?;
                        if locations.len() == 1 {
                            Ok(Driver::new(
                                self.program.clone(),
                                locations[0].clone().into(),
                                successor.into(),
                                self.architecture,
                            ))
                        } else {
                            // every location should be an edge, and only one
                            // edge should be satisfiable
                            for location in locations {
                                if let il::RefFunctionLocation::Edge(edge) =
                                    *location.function_location()
                                {
                                    if successor
                                        .state()
                                        .symbolize_and_eval(
                                            edge.condition()
                                                .ok_or("Failed to get edge condition")?,
                                        )?
                                        .is_one()
                                    {
                                        return Ok(Driver::new(
                                            self.program.clone(),
                                            location.clone().into(),
                                            successor.into(),
                                            self.architecture,
                                        ));
                                    }
                                }
                            }
                            Err(Error::ExecutorNoValidLocation)
                        }
                    }
                    SuccessorType::Branch(address) => {
                        match il::RefProgramLocation::from_address(&self.program, address) {
                            Some(location) => Ok(Driver::new(
                                self.program.clone(),
                                location.into(),
                                successor.into(),
                                self.architecture,
                            )),
                            None => {
                                let state: State = successor.into();
                                let function = self
                                    .architecture
                                    .translator()
                                    .translate_function(state.memory(), address)
                                    .map_err(|e| Error::ExecutorLiftFail(address, Box::new(e)))?;
                                let mut program = self.program.clone();
                                RC::make_mut(&mut program).add_function(function);
                                let location: il::ProgramLocation =
                                    il::RefProgramLocation::from_address(&program, address)
                                        .ok_or("Failed to get location for newly lifted function")?
                                        .into();
                                Ok(Driver::new(program, location, state, self.architecture))
                            }
                        }
                    }
                    SuccessorType::Intrinsic(ref intrinsic) => Err(Error::UnhandledIntrinsic(
                        intrinsic.instruction_str().to_string(),
                    )),
                }
            }
            il::RefFunctionLocation::Edge(_) => {
                let locations = location.forward()?;
                Ok(Driver::new(
                    self.program.clone(),
                    locations[0].clone().into(),
                    self.state,
                    self.architecture,
                ))
            }
            il::RefFunctionLocation::EmptyBlock(_) => {
                let locations = location.forward()?;
                if locations.len() == 1 {
                    return Ok(Driver::new(
                        self.program.clone(),
                        locations[0].clone().into(),
                        self.state,
                        self.architecture,
                    ));
                } else {
                    for location in locations {
                        if let il::RefFunctionLocation::Edge(edge) = *location.function_location() {
                            if self
                                .state
                                .symbolize_and_eval(
                                    edge.condition().ok_or(Error::ExecutorNoEdgeCondition)?,
                                )?
                                .is_one()
                            {
                                return Ok(Driver::new(
                                    self.program.clone(),
                                    location.clone().into(),
                                    self.state,
                                    self.architecture,
                                ));
                            }
                        }
                    }
                }
                Err(Error::ExecutorNoValidLocation)
            }
        }
    }

    /// Retrieve the Falcon IL program associated with this driver.
    pub fn program(&self) -> &il::Program {
        &self.program
    }

    /// If this driver is sitting on an instruction with an address, return
    /// that address.
    pub fn address(&self) -> Option<u64> {
        self.location
            .apply(&self.program)
            .expect("Failed to apply program location")
            .address()
    }

    /// Retrieve the `il::ProgramLocation` associated with this driver.
    pub fn location(&self) -> &il::ProgramLocation {
        &self.location
    }

    /// Retrieve the concrete `State` associated with this driver.
    pub fn state(&self) -> &State {
        &self.state
    }

    /// Retrieve a mutable reference to the `State` associated with this driver.
    pub fn state_mut(&mut self) -> &mut State {
        &mut self.state
    }
}
