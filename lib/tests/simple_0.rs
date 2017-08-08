#[cfg(test)]use error::*;
#[cfg(test)]use engine;
#[cfg(test)]use engine::*;
#[cfg(test)]use il;
#[cfg(test)]use loader;
#[cfg(test)]use loader::Loader;
#[cfg(test)]use platform::*;
#[cfg(test)]use std::path::Path;
#[cfg(test)]use std::rc::Rc;


#[cfg(test)]
fn simple_0_test () -> Result<Vec<u8>> {
    // let filename = Path::new("test_binaries/Palindrome/Palindrome.json");
    // let elf = ::falcon::loader::json::Json::from_file(filename)?;
    let filename = Path::new("test_binaries/simple-0/simple-0");
    let elf = loader::elf::ElfLinker::new(filename)?;
    // let mut elf = ::falcon::loader::elf::Elf::from_file(filename)?;

    let mut program = il::Program::new();
    program.add_function(elf.function(elf.program_entry())?);

    // Initialize memory.
    let mut memory = SymbolicMemory::new(engine::Endian::Little);

    // Load all memory as given by the loader.
    for (address, segment) in elf.memory()?.segments() {
        let bytes = segment.bytes();
        for i in 0..bytes.len() {
            memory.store(*address + i as u64, il::expr_const(bytes[i] as u64, 8))?;
        }
    }


    let mut platform = linux_x86::LinuxX86::new();
    
    // Create the engine
    let mut engine = SymbolicEngine::new(memory);
    platform.initialize(&mut engine)?;


    // Get the first instruction we care about
    let pl = ProgramLocation::from_address(elf.program_entry(), &program).unwrap();
    // let pl = ProgramLocation::from_address(0x804880f, &program).unwrap();
    let translator = elf.translator()?;
    let driver = EngineDriver::new(
        Rc::new(program),
        pl,
        engine,
        &translator,
        Rc::new(platform)
    );
    let mut drivers = vec![driver];

    let target_address: u64 = 0x8048512;

    loop {
        let mut new_drivers = Vec::new();
        for driver in drivers {
            {
                let location = driver.location();
                let program = driver.program();
                let function_location = location.function_location();
                if let FunctionLocation::Instruction{block_index, instruction_index} = *function_location {
                    let function = program.function(location.function_index()).unwrap();
                    let block = function.block(block_index).unwrap();
                    let instruction = block.instruction(instruction_index).unwrap();
                    let address = instruction.address().unwrap();
                    if address == target_address {
                        println!("Reached Target Address");
                        for constraint in driver.engine().constraints() {
                            println!("Constraint: {}", constraint);
                        }
                        let mut stdin: Vec<u8> = Vec::new();
                        for scalar in driver.platform().symbolic_scalars() {
                            let byte = driver.engine().eval(&scalar.clone().into(), None)?.unwrap();
                            assert!(byte.bits() == 8);
                            stdin.push(byte.value() as u8);
                        }
                        return Ok(stdin);
                    }
                }
            }
            new_drivers.append(&mut driver.step()?);
        }
        drivers = new_drivers;
        if drivers.is_empty() {
            break;
        }
    }

    bail!("Did not find result")
}


#[test]
pub fn engine_test () -> () {
    let result: Vec<u8> = vec![0x61, 0x62, 0x63, 0x64 ,0x65, 0x66, 0x67, 0x68];
    let found = simple_0_test();
    assert!(found.is_ok());

    let found = found.unwrap();

    for i in 0..result.len() {
        println!("{} {}", result[i], found[i]);
        assert!(result[i] == found[i]);
    }
}

