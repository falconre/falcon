use error::*;
use falcon::engine::*;
use falcon::il;
use falcon::loader::Loader;
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
    let mut i = 0;
    for instruction in control_flow_graph.block(ia.1)?.instructions() {
        println!("Executing {}", instruction);
        let mut successors = engine.execute(instruction.operation())?;
        if successors.is_empty() {
            panic!("No successors");
        }
        if successors.len() > 1 {
            panic!("More than one successor");
        }
        let successor = successors.remove(0);
        engine = match *successor.successor_type() {
            SuccessorType::FallThrough => successor.into_engine(),
            SuccessorType::Branch(address) =>
                panic!("SuccessorType::Branch {}", address)
        };
        i = i + 1;
        if i > 0x20 {
            break;
        }
    }

    Ok(())
}

