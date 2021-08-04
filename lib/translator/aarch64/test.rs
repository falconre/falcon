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
        .chain(Some(&NOP))
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

#[test]
fn add_xn_lsl() {
    // add x0, xzr, x0, lsl #28
    let instruction_words = &[0x8b0073e0];

    let result = get_scalar(
        instruction_words,
        vec![("x0", const_(0xbeef000000, 64))],
        Memory::new(Endian::Big),
        "x0",
    );
    assert_eq!(result.value_u64().unwrap(), 0xeef0000000000000);
}

#[test]
fn add_xn_lsr() {
    // add x0, xzr, x0, lsr #24
    let instruction_words = &[0x8b4063e0];

    let result = get_scalar(
        instruction_words,
        vec![("x0", const_(0x12345678u64.wrapping_neg(), 64))],
        Memory::new(Endian::Big),
        "x0",
    );
    assert_eq!(result.value_u64().unwrap(), 0x000000ffffffffed);
}

#[test]
fn add_xn_asr() {
    // add x0, xzr, x0, asr #24
    let instruction_words = &[0x8b8063e0];

    let result = get_scalar(
        instruction_words,
        vec![("x0", const_(0x12345678u64.wrapping_neg(), 64))],
        Memory::new(Endian::Big),
        "x0",
    );
    assert_eq!(result.value_u64().unwrap(), 0xffffffffffffffed);
}

// TODO: test `ror` shift

#[test]
fn add_xn_sxtx() {
    // add x0, x1, x0, sxtx #0x3
    let instruction_words = &[0x8b20ec20];

    let result = get_scalar(
        instruction_words,
        vec![
            ("x0", const_(0x1111444422228888, 64)),
            ("x1", const_(0, 64)),
        ],
        Memory::new(Endian::Big),
        "x0",
    );
    assert_eq!(result.value_u64().unwrap(), 0x888a222111144440);
}

#[test]
fn add_xn_xn_sxtx() {
    // add x0, x1, x0, sxtx #0x3
    let instruction_words = &[0x8b20ec20];

    let result = get_scalar(
        instruction_words,
        vec![
            ("x0", const_(0x1111444422228888, 64)),
            ("x1", const_(0, 64)),
        ],
        Memory::new(Endian::Big),
        "x0",
    );
    assert_eq!(result.value_u64().unwrap(), 0x888a222111144440);
}

#[test]
fn add_xn_wn_sxtw() {
    // add x0, x1, w0, sxtw #0x3
    let instruction_words = &[0x8b20cc20];

    let result = get_scalar(
        instruction_words,
        vec![
            ("x0", const_(0x11114444ffff8888, 64)),
            ("x1", const_(0, 64)),
        ],
        Memory::new(Endian::Big),
        "x0",
    );
    assert_eq!(result.value_u64().unwrap(), 0xfffffffffffc4440);
}

#[test]
fn add_xn_wn_sxth() {
    // add x0, x1, w0, sxth #0x3
    let instruction_words = &[0x8b20ac20];

    let result = get_scalar(
        instruction_words,
        vec![
            ("x0", const_(0xffff00000000fedc, 64)),
            ("x1", const_(0, 64)),
        ],
        Memory::new(Endian::Big),
        "x0",
    );
    assert_eq!(result.value_u64().unwrap(), 0xfffffffffffff6e0);
}

#[test]
fn add_xn_wn_sxtb() {
    // add x0, x1, w0, sxtb #0x3
    let instruction_words = &[0x8b208c20];

    let result = get_scalar(
        instruction_words,
        vec![
            ("x0", const_(0xffff00000000fedc, 64)),
            ("x1", const_(0, 64)),
        ],
        Memory::new(Endian::Big),
        "x0",
    );
    assert_eq!(result.value_u64().unwrap(), 0xfffffffffffffee0);
}

#[test]
fn add_xn_uxtx() {
    // add x0, x1, x0, uxtx #0x3
    let instruction_words = &[0x8b206c20];

    let result = get_scalar(
        instruction_words,
        vec![
            ("x0", const_(0x1111444422228888, 64)),
            ("x1", const_(0, 64)),
        ],
        Memory::new(Endian::Big),
        "x0",
    );
    assert_eq!(result.value_u64().unwrap(), 0x888a222111144440);
}

#[test]
fn add_xn_uxtw() {
    // add x0, x1, w0, uxtw #0x3
    let instruction_words = &[0x8b204c20];

    let result = get_scalar(
        instruction_words,
        vec![
            ("x0", const_(0x11114444ffff8888, 64)),
            ("x1", const_(0, 64)),
        ],
        Memory::new(Endian::Big),
        "x0",
    );
    assert_eq!(result.value_u64().unwrap(), 0x00000007fffc4440);
}

#[test]
fn add_xn_uxth() {
    // add x0, x1, w0, uxth #0x3
    let instruction_words = &[0x8b202c20];

    let result = get_scalar(
        instruction_words,
        vec![
            ("x0", const_(0xffff00000000fedc, 64)),
            ("x1", const_(0, 64)),
        ],
        Memory::new(Endian::Big),
        "x0",
    );
    assert_eq!(result.value_u64().unwrap(), 0x000000000007f6e0);
}

#[test]
fn add_xn_uxtb() {
    // add x0, x1, w0, uxtb #0x3
    let instruction_words = &[0x8b200c20];

    let result = get_scalar(
        instruction_words,
        vec![
            ("x0", const_(0xffff00000000fedc, 64)),
            ("x1", const_(0, 64)),
        ],
        Memory::new(Endian::Big),
        "x0",
    );
    assert_eq!(result.value_u64().unwrap(), 0x00000000000006e0);
}

#[test]
fn b() {
    //   b 1f
    //   mov x3, #2
    // 1:
    let instruction_words = &[0x14000002, 0xd2800043];

    let result = get_scalar(
        instruction_words,
        vec![("x3", const_(1, 64))],
        Memory::new(Endian::Big),
        "x3",
    );
    assert_eq!(result.value_u64().unwrap(), 1);
}

#[test]
fn bl_ret() {
    //   b 1f
    // 0:
    //   mov x25, #2
    //   ret
    // 1:
    //   mov x25, #1
    //   bl 0b
    //   add x25, #8
    let instruction_words = &[
        0x14000003, 0xd2800059, 0xd65f03c0, 0xd2800039, 0x97fffffd, 0x91002339,
    ];

    let result = get_scalar(
        instruction_words,
        vec![("x25", const_(42, 64))],
        Memory::new(Endian::Big),
        "x25",
    );
    assert_eq!(result.value_u64().unwrap(), 10);
}

#[test]
fn mov_velem() {
    // mov v31.d[0], x0
    // mov v31.b[6], v31.b[2]
    // mov w29, v31.s[1]
    let instruction_words = &[0x4e081c1f, 0x6e0d17ff, 0x0e0c3ffd];

    let result = get_scalar(
        instruction_words,
        vec![
            ("x0", const_(0x62d8ced391ba44f3, 64)),
            ("v31", const_(0x51aad564c6b04cbd, 128)),
        ],
        Memory::new(Endian::Big),
        "x29",
    );
    assert_eq!(result.value_u64().unwrap(), 0x0000000062baced3);
}

#[test]
fn sub_xn() {
    // sub x0, x1, x2
    let instruction_words = &[0xcb020020];

    let result = get_scalar(
        instruction_words,
        vec![
            ("x0", const_(0x67eccf9f6c8e4aee, 64)),
            ("x1", const_(0x297feae8ee50966c, 64)),
            ("x2", const_(0x968855acc9024e5c, 64)),
        ],
        Memory::new(Endian::Big),
        "x0",
    );
    assert_eq!(result.value_u64().unwrap(), 0x92f7953c254e4810);
}

// TODO: rest of the instructions
