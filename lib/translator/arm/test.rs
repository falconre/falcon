use architecture;
use architecture::Endian;
use executor::*;
use il::*;
use memory;
use translator::arm::*;
use RC;

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
    instruction_bytes: &[u8],
    scalars: Vec<(&str, Constant)>,
    memory_: Memory,
) -> Driver {
    let mut bytes = instruction_bytes.to_vec();
    // orr r0, r0, r0
    bytes.append(&mut vec![0xe1, 0x80, 0x00, 0x00]);

    let mut backing = memory::backing::Memory::new(Endian::Big);
    backing.set_memory(
        0,
        bytes.to_vec(),
        memory::MemoryPermissions::EXECUTE | memory::MemoryPermissions::READ,
    );

    let function = Arm::new().translate_function(&backing, 0).unwrap();

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
        RC::new(architecture::Arm::new()),
    )
}

fn init_driver_function(
    backing: memory::backing::Memory,
    scalars: Vec<(&str, Constant)>,
) -> Driver {
    let memory = Memory::new_with_backing(Endian::Big, RC::new(backing));

    let function = Arm::new().translate_function(&memory, 0).unwrap();
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
        RC::new(architecture::Arm::new()),
    )
}

fn get_scalar(
    instruction_bytes: &[u8],
    scalars: Vec<(&str, Constant)>,
    memory: Memory,
    result_scalar: &str,
) -> Constant {
    let mut driver = init_driver_block(instruction_bytes, scalars, memory);

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
    instruction_bytes: &[u8],
    scalars: Vec<(&str, Constant)>,
    memory: Memory,
) -> Intrinsic {
    let mut driver = init_driver_block(instruction_bytes, scalars, memory);

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
fn adc() {
    // add r0, r1, r2
    let instruction_bytes = &[0xe0, 0xa1, 0x00, 0x02];

    let result = get_scalar(
        instruction_bytes,
        vec![
            ("r1", const_(1, 32)),
            ("r2", const_(2, 32)),
            ("C", const_(1, 1)),
        ],
        Memory::new(Endian::Big),
        "r0",
    );
    assert_eq!(result.value_u64().unwrap(), 4);
}

#[test]
fn add() {
    // add r0, r1, r2
    let instruction_bytes = &[0xe0, 0x81, 0x00, 0x02];

    let result = get_scalar(
        instruction_bytes,
        vec![("r1", const_(1, 32)), ("r2", const_(2, 32))],
        Memory::new(Endian::Big),
        "r0",
    );
    assert_eq!(result.value_u64().unwrap(), 3);
}

#[test]
fn and() {
    // and r0, r1, r2
    let instruction_bytes = &[0xe0, 0x01, 0x00, 0x02];

    let result = get_scalar(
        instruction_bytes,
        vec![
            ("r1", const_(0xffff0000, 32)),
            ("r2", const_(0x00ff00ff, 32)),
        ],
        Memory::new(Endian::Big),
        "r0",
    );
    assert_eq!(result.value_u64().unwrap(), 0x00ff0000);
}
