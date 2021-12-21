use crate::architecture;
use crate::architecture::Endian;
use crate::executor::*;
use crate::il::*;
use crate::memory;
use crate::translator::ppc::*;
use crate::RC;

fn init_driver_block<'d>(
    instruction_bytes: &[u8],
    scalars: Vec<(&str, Constant)>,
    memory_: Memory,
) -> Driver {
    let mut bytes = instruction_bytes.to_vec();
    // ori 0,0,0
    bytes.append(&mut vec![0x60, 0x00, 0x00, 0x00]);

    let mut backing = memory::backing::Memory::new(Endian::Big);
    backing.set_memory(
        0,
        bytes.to_vec(),
        memory::MemoryPermissions::EXECUTE | memory::MemoryPermissions::READ,
    );

    let function = Ppc::new().translate_function(&backing, 0).unwrap();

    let location = if function
        .control_flow_graph()
        .block(0)
        .unwrap()
        .instructions()
        .is_empty()
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
        RC::new(architecture::Ppc::new()),
    )
}

fn get_scalar(
    instruction_bytes: &[u8],
    scalars: Vec<(&str, Constant)>,
    memory: Memory,
    result_scalar: &str,
) -> Constant {
    let mut driver = init_driver_block(instruction_bytes, scalars, memory);

    while !driver
        .location()
        .apply(driver.program())
        .unwrap()
        .forward()
        .unwrap()
        .is_empty()
    {
        driver = driver.step().unwrap();
    }
    // The final step
    // driver = driver.step().unwrap();

    driver.state().get_scalar(result_scalar).unwrap().clone()
}

#[test]
fn rlwinm() {
    // rlwinm 6,4,2,0,0x1D
    let instruction_bytes = &[0x54, 0x86, 0x10, 0x3a];

    let result = get_scalar(
        instruction_bytes,
        vec![
            ("r4", const_(0x9000_3000, 32)),
            ("r6", const_(0xffff_ffff, 32)),
        ],
        Memory::new(Endian::Big),
        "r6",
    );
    assert_eq!(result.value_u64().unwrap(), 0x4000_c000);

    let result = get_scalar(
        instruction_bytes,
        vec![
            ("r4", const_(0xb004_3000, 32)),
            ("r6", const_(0xffff_ffff, 32)),
        ],
        Memory::new(Endian::Big),
        "r6",
    );
    assert_eq!(result.value_u64().unwrap(), 0xc010_c000);
}
