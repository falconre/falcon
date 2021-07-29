use crate::architecture;
use crate::architecture::Endian;
use crate::executor::*;
use crate::il::*;
use crate::memory;
use crate::translator::aarch64::*;
use crate::RC;

#[macro_use]
macro_rules! backing {
    ($e: expr) => {{
        let v: Vec<u8> = $e.to_vec();
        let mut b = memory::backing::Memory::new(Endian::Big);
        b.set_memory(0, v, memory::MemoryPermissions::EXECUTE);
        b
    }};
}

fn init_driver_block<'d>(
    instruction_words: &[u32],
    scalars: Vec<(&str, Constant)>,
    memory_: Memory,
) -> Driver {
    const NOP: u32 = 0xd503201f;
    let bytes: Vec<u8> = instruction_words
        .iter()
        // The following code can be rewritten as `encoding.to_le_bytes()
        // .into_iter()` in Rust 2021 but not in Rust 2018
        .map(|encoding| IntoIterator::into_iter(encoding.to_le_bytes()))
        .flatten()
        .collect();

    let mut backing = memory::backing::Memory::new(Endian::Big);
    backing.set_memory(
        0,
        bytes,
        memory::MemoryPermissions::EXECUTE | memory::MemoryPermissions::READ,
    );

    let function = AArch64::new().translate_function(&backing, 0).unwrap();

    let location = if function
        .control_flow_graph()
        .block(0)
        .unwrap()
        .instructions()
        .len()
        == 0
    {
        ProgramLocation::new(Some(0), FunctionLocation::EmptyBlock(0))
    } else {
        ProgramLocation::new(Some(0), FunctionLocation::Instruction(0, 0))
    };

    let mut program = Program::new();
    program.add_function(function);

    let mut state = State::new(memory_);
    for scalar in scalars {
        state.set_scalar(scalar.0, scalar.1);
    }

    Driver::new(
        RC::new(program),
        location,
        state,
        RC::new(architecture::AArch64::new()),
    )
}

fn init_driver_function(
    backing: memory::backing::Memory,
    scalars: Vec<(&str, Constant)>,
) -> Driver {
    let memory = Memory::new_with_backing(Endian::Big, RC::new(backing));

    let function = AArch64::new().translate_function(&memory, 0).unwrap();
    let mut program = Program::new();

    program.add_function(function);

    let location = ProgramLocation::new(Some(0), FunctionLocation::Instruction(0, 0));

    let mut state = State::new(memory);
    for scalar in scalars {
        state.set_scalar(scalar.0, scalar.1);
    }

    Driver::new(
        RC::new(program),
        location,
        state,
        RC::new(architecture::AArch64::new()),
    )
}

fn get_scalar(
    instruction_words: &[u32],
    scalars: Vec<(&str, Constant)>,
    memory: Memory,
    result_scalar: &str,
) -> Constant {
    let mut driver = init_driver_block(instruction_words, scalars, memory);

    while driver
        .location()
        .apply(driver.program())
        .unwrap()
        .forward()
        .unwrap()
        .len()
        > 0
    {
        driver = driver.step().unwrap();
    }
    // The final step
    // driver = driver.step().unwrap();

    driver.state().get_scalar(result_scalar).unwrap().clone()
}

fn get_intrinsic(
    instruction_words: &[u32],
    scalars: Vec<(&str, Constant)>,
    memory: Memory,
) -> Intrinsic {
    let mut driver = init_driver_block(instruction_words, scalars, memory);

    loop {
        {
            let location = driver.location().apply(driver.program()).unwrap();
            if let Some(instruction) = location.instruction() {
                if let Operation::Intrinsic { ref intrinsic } = *instruction.operation() {
                    return intrinsic.clone();
                }
            }
        }
        driver = driver.step().unwrap();
    }
}

fn step_to(mut driver: Driver, target_address: u64) -> Driver {
    loop {
        driver = driver.step().unwrap();
        if let Some(address) = driver.location().apply(driver.program()).unwrap().address() {
            if address == target_address {
                return driver;
            }
        }
    }
}

#[test]
fn add_xn() {
    // add x0, x1, x2
    let instruction_words = &[0x8b020020];

    let result = get_scalar(
        instruction_words,
        vec![("x1", const_(1, 64)), ("x2", const_(3, 64))],
        Memory::new(Endian::Big),
        "x0",
    );
    assert_eq!(result.value_u64().unwrap(), 4);

    let result = get_scalar(
        instruction_words,
        vec![("x1", const_(42, 64)), ("x2", const_(u64::MAX, 64))],
        Memory::new(Endian::Big),
        "x0",
    );
    assert_eq!(result.value_u64().unwrap(), u64::MAX.wrapping_add(42));
}

// TODO: rest of the instructions
