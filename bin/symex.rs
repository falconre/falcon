use error::*;
use falcon::engine::*;
use falcon::executor;
use falcon::il;
use falcon::loader::Loader;
use falcon::platform::*;
use std::rc::Rc;
use std::path::Path;


use engine_driver::*;



pub fn engine_test () -> Result<()> {
    // let filename = Path::new("test_binaries/Palindrome/Palindrome.json");
    // let elf = ::falcon::loader::json::Json::from_file(filename)?;
    let filename = Path::new("test_binaries/simple-0/simple-0");
    let elf = ::falcon::loader::elf::ElfLinker::new(filename)?;
    // let mut elf = ::falcon::loader::elf::Elf::from_file(filename)?;

    let program = elf.to_program()?;

    // Initialize memory.
    let mut memory = SymbolicMemory::new(32, ::falcon::engine::Endian::Little);

    // Load all memory as given by the loader.
    for (address, segment) in elf.memory()?.segments() {
        let bytes = segment.bytes();
        for i in 0..bytes.len() {
            memory.store(*address + i as u64, il::expr_const(bytes[i] as u64, 8))?;
        }
    }

    // Set up space for fs/gs from 0xbf000000 to 0xbf010000
    for i in 0..0x10000 {
        memory.store((0xbf000000 as u64 + i as u64), il::expr_const(0, 8))?;
    }


    let mut platform = linux_x86::LinuxX86::new();
    
    // Create the engine
    let mut engine = SymbolicEngine::new(memory);
    platform.initialize(&mut engine)?;


    // Get the first instruction we care about
    let pl = ProgramLocation::from_address(elf.program_entry(), &program).unwrap();
    // let pl = ProgramLocation::from_address(0x804880f, &program).unwrap();
    let translator = elf.translator()?;
    let driver = EngineDriver::new(Rc::new(program), pl, engine, &translator);
    let mut drivers = vec![driver];

    loop {
        let mut new_drivers = Vec::new();
        for driver in drivers {
            new_drivers.append(&mut driver.step()?);
        }
        drivers = new_drivers;
        if drivers.is_empty() {
            break;
        }
    }

    Ok(())
}

