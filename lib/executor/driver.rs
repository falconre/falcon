//! A driver concretely executes a Falcon IL programs.

use architecture::Architecture;
use error::*;
use executor::State;
use executor::successor::*;
use il;
use RC;

/// A driver for a concrete executor over Falcon IL.
#[derive(Debug, Clone)]
pub struct Driver<'d> {
    program: RC<il::Program>,
    location: il::ProgramLocation,
    state: State<'d>,
    architecture: RC<Architecture>,
}


impl<'d> Driver<'d> {
    /// Create a new driver for concrete execution over Falcon IL.
    pub fn new(
        program: RC<il::Program>,
        location: il::ProgramLocation,
        state: State<'d>,
        architecture: RC<Architecture>,
    ) -> Driver {
        Driver {
            program: program,
            location: location,
            state: state,
            architecture: architecture
        }
    }

    /// Step forward over Falcon IL.
    pub fn step(self) -> Result<Driver<'d>> {
        let location = self.location.apply(&self.program).unwrap();
        match *location.function_location() {
            il::RefFunctionLocation::Instruction(_, instruction) => {
                let successor = self.state.execute(instruction.operation())?;

                match successor.type_().clone() {
                    SuccessorType::FallThrough => {
                        let locations = location.forward()?;
                        if locations.len() == 1 {
                            return Ok(Driver::new(
                                self.program.clone(),
                                locations[0].clone().into(),
                                successor.into(),
                                self.architecture
                            ));
                        }
                        else {
                            // every location should be an edge, and only one
                            // edge should be satisfiable
                            for location in locations {
                                if let il::RefFunctionLocation::Edge(edge) = *location.function_location() {
                                    if successor.state()
                                                .symbolize_and_eval(&edge.condition().clone().unwrap())?
                                                .value() == 1 {
                                        return Ok(Driver::new(
                                            self.program.clone(),
                                            location.clone().into(),
                                            successor.into(),
                                            self.architecture
                                        ));
                                    }
                                }
                            }
                            bail!("No valid successor location found on fall through");
                        }
                    },
                    SuccessorType::Branch(address) => {
                        match il::RefProgramLocation::from_address(&self.program, address) {
                            Some(location) => return Ok(Driver::new(
                                self.program.clone(),
                                location.into(),
                                successor.into(),
                                self.architecture
                            )),
                            None => {
                                let state: State = successor.into();
                                let function = self.architecture
                                                   .translator()
                                                   .translate_function(state.memory(), address)
                                                   .expect(&format!("Failed to lift function at 0x{:x}", address));
                                let mut program = self.program.clone();
                                RC::make_mut(&mut program).add_function(function);
                                let location = il::RefProgramLocation::from_address(
                                    &program,
                                    address
                                );
                                return Ok(Driver::new(
                                    program.clone(),
                                    location.unwrap().into(),
                                    state,
                                    self.architecture
                                ));
                            }
                        }
                    },
                    SuccessorType::Raise(ref expression) => {
                        bail!(format!("Raise is unimplemented, {}", expression));
                    }
                }
            },
            il::RefFunctionLocation::Edge(_) => {
                let locations = location.forward()?;
                return Ok(Driver::new(
                    self.program.clone(),
                    locations[0].clone().into(),
                    self.state,
                    self.architecture
                ));
            },
            il::RefFunctionLocation::EmptyBlock(_) => {
                let locations = location.forward()?;
                if locations.len() == 1 {
                    return Ok(Driver::new(
                        self.program.clone(),
                        locations[0].clone().into(),
                        self.state,
                        self.architecture
                    ));
                }
                else {
                    for location in locations {
                        if let il::RefFunctionLocation::Edge(edge) = *location.function_location() {
                            if self.state
                                   .symbolize_and_eval(&edge.condition().clone().unwrap())?
                                   .value() == 1 {
                                return Ok(Driver::new(
                                    self.program.clone(),
                                    location.clone().into(),
                                    self.state,
                                    self.architecture
                                ));
                            }
                        }
                    }
                }
                bail!("No valid location out of empty block");
            }
        }
    }

    /// Retrieve the Falcon IL program associated with this driver.
    pub fn program(&self) -> &il::Program {
        &self.program
    }

    /// Retrieve the `il::ProgramLocation` associated with this driver.
    pub fn location(&self) -> &il::ProgramLocation {
        &self.location
    }

    /// Retrieve the concrete `State` associated with this driver.
    pub fn state(&self) -> &State {
        &self.state
    }
}