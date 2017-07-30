use error::*;
use falcon::engine::*;
use falcon::executor;
use falcon::il;
use falcon::loader::Loader;
use std::rc::Rc;
use std::path::Path;


use engine_driver::*;


const STACK_ADDRESS: u64 = 0xb0000000;
const STACK_SIZE: u64 = 0x10000;
const INITIAL_STACK_POINTER: u64 = STACK_ADDRESS - 0x1000;

const FS_BASE: u64 = 0xbf000000;
const FS_SIZE: u64 = 0x8000;
const GS_BASE: u64 = 0xbf008000;
const GS_SIZE: u64 = 0x8000;

const KERNEL_VSYSCALL_BYTES: &'static [u8] = &[0x0f, 0x34, 0xc3];
const KERNEL_VSYSCALL_ADDRESS: u64 = 0xbfff0000;


fn push(engine: &mut SymbolicEngine, value: u32) -> Result<()> {
    let expr = match engine.get_scalar_only_concrete("esp")? {
        Some(expr) => expr,
        None => bail!("Could not get concrete value for esp")
    };

    let address = expr.value() - 4;

    engine.set_scalar("esp", il::Expression::constant(
        executor::constants_expression(
            &il::Expression::sub(
                il::Expression::constant(expr),
                il::expr_const(4, 32)
            )?
        )?
    ));

    engine.memory_mut().store(address, il::expr_const(value as u64, 32))?;

    Ok(())
}


fn initialize_stack(engine: &mut SymbolicEngine) -> Result<()> {
    for i in 0..STACK_SIZE {
        engine.memory_mut().store(STACK_ADDRESS - STACK_SIZE + i, il::expr_const(0, 8))?;
    }

    engine.set_scalar("esp", il::expr_const(INITIAL_STACK_POINTER, 32));

    Ok(())
}


fn initialize_segments(engine: &mut SymbolicEngine) -> Result<()> {
    for i in 0..FS_SIZE {
        engine.memory_mut().store(FS_BASE - FS_SIZE + i, il::expr_const(0, 8))?;
    }

    for i in 0..GS_SIZE {
        engine.memory_mut().store(GS_BASE - GS_SIZE + i, il::expr_const(0, 8))?;
    }

    engine.set_scalar("fs_base", il::expr_const(FS_BASE, 32));
    engine.set_scalar("gs_base", il::expr_const(GS_BASE, 32));

    Ok(())
}


fn initialize_miscellaneous(engine: &mut SymbolicEngine) -> Result<()> {
    engine.set_scalar("DF", il::expr_const(0, 1));

    /* SVR4/i386 ABI (pages 3-31, 3-32) says that when the program
    starts %edx contains a pointer to a function
    which might be registered using atexit.
    This provides a mean for the dynamic linker to call
    DT_FINI functions for shared libraries that
    have been loaded before the code runs.
    A value of 0 tells we have no such handler.
    */
    engine.set_scalar("edx", il::expr_const(0, 32));

    Ok(())
}


fn initialize_command_line_arguments(engine: &mut SymbolicEngine) -> Result<()> {
    push(engine, 0)?;
    push(engine, 0)?;
    Ok(())
}


fn initialize_environment_variables(engine: &mut SymbolicEngine) -> Result<()> {
    push(engine, 0)?;
    Ok(())
}


fn initialize_kernel_vsyscall(engine: &mut SymbolicEngine) -> Result<()> {
    // Set up the KERNEL_VSYSCALL function
    for i in 0..KERNEL_VSYSCALL_BYTES.len() {
        println!("writing 0x{:02x} at 0x{:08x}",
            KERNEL_VSYSCALL_BYTES[i],
            KERNEL_VSYSCALL_ADDRESS + i as u64);
        engine.memory_mut().store(
            KERNEL_VSYSCALL_ADDRESS + i as u64,
            il::expr_const(KERNEL_VSYSCALL_BYTES[i] as u64, 8)
        )?;
    }
    // Set up a fake AT_SYSINFO 0x100 bytes ahead of vsyscall
    engine.memory_mut().store(
        KERNEL_VSYSCALL_ADDRESS + 0x100,
        il::expr_const(32, 32) // 32 = AT_SYSINFO
    )?;
    engine.memory_mut().store(
        KERNEL_VSYSCALL_ADDRESS + 0x104,
        il::expr_const(KERNEL_VSYSCALL_ADDRESS, 32)
    )?;
    // Push AT_SYSINFO onto stack
    push(engine, (KERNEL_VSYSCALL_ADDRESS + 0x100) as u32)?;
    push(engine, 0)?;
    
    // HACK (I think, need to know more about linux vsyscall process)
    // set gs + 0x10 tp KERNEL_VSYSCALL_ADDRESS
    let expr = match engine.get_scalar_only_concrete("gs_base")? {
        Some(expr) => expr,
        None => bail!("Could not get concrete value for gs_base")
    };

    let address = expr.value() + 0x10;

    engine.memory_mut().store(address, il::expr_const(KERNEL_VSYSCALL_ADDRESS, 32))?;

    Ok(())
}



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

    // Create the engine
    let mut engine = SymbolicEngine::new(memory);

    initialize_stack(&mut engine)?;
    initialize_segments(&mut engine)?;
    initialize_miscellaneous(&mut engine)?;

    initialize_command_line_arguments(&mut engine)?;
    initialize_environment_variables(&mut engine)?;
    initialize_kernel_vsyscall(&mut engine)?;

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

