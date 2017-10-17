use error::*;
use executor::engine::Engine;
use executor::successor::*;
use il;
use RC;
use types::Architecture;

#[derive(Debug, Clone)]
pub struct Driver {
    program: RC<il::Program>,
    location: il::ProgramLocation,
    engine: Engine,
    architecture: Architecture,
}


impl Driver {
    pub fn new(
        program: RC<il::Program>,
        location: il::ProgramLocation,
        engine: Engine,
        architecture: Architecture,
    ) -> Driver {
        Driver {
            program: program,
            location: location,
            engine: engine,
            architecture: architecture
        }
    }


    pub fn step(self) -> Result<Driver> {
        let location = self.location.apply(&self.program).unwrap();
        match *location.function_location() {
            il::RefFunctionLocation::Instruction(_, instruction) => {
                let successor = self.engine.execute(instruction.operation())?;

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
                                    if successor.engine()
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
                                let engine: Engine = successor.into();
                                let function = self.architecture
                                                   .translator()
                                                   .translate_function(engine.memory(), address)
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
                                    engine,
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
                    self.engine,
                    self.architecture
                ));
            },
            il::RefFunctionLocation::EmptyBlock(_) => {
                let locations = location.forward()?;
                if locations.len() == 1 {
                    return Ok(Driver::new(
                        self.program.clone(),
                        locations[0].clone().into(),
                        self.engine,
                        self.architecture
                    ));
                }
                else {
                    for location in locations {
                        if let il::RefFunctionLocation::Edge(edge) = *location.function_location() {
                            if self.engine
                                   .symbolize_and_eval(&edge.condition().clone().unwrap())?
                                   .value() == 1 {
                                return Ok(Driver::new(
                                    self.program.clone(),
                                    location.clone().into(),
                                    self.engine,
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

    pub fn program(&self) -> &il::Program {
        &self.program
    }

    pub fn location(&self) -> &il::ProgramLocation {
        &self.location
    }

    pub fn engine(&self) -> &Engine {
        &self.engine
    }
}