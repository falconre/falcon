use crate::architecture;
use crate::architecture::Endian;
use crate::executor::*;
use crate::il::*;
use crate::memory;
use crate::translator::aarch64::*;
use crate::RC;

macro_rules! backing {
    ($e: expr) => {{
        let words: &[u32] = $e;
        let v: Vec<u8> = words.iter().map(|w| w.to_le_bytes()).flatten().collect();
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

// fn get_intrinsic(
//     instruction_words: &[u32],
//     scalars: Vec<(&str, Constant)>,
//     memory: Memory,
// ) -> Intrinsic {
//     let mut driver = init_driver_block(instruction_words, scalars, memory);

//     loop {
//         {
//             let location = driver.location().apply(driver.program()).unwrap();
//             if let Some(instruction) = location.instruction() {
//                 if let Operation::Intrinsic { ref intrinsic } = *instruction.operation() {
//                     return intrinsic.clone();
//                 }
//             }
//         }
//         driver = driver.step().unwrap();
//     }
// }

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

fn memval(memory: &Memory, address: u64, bits: usize) -> u128 {
    memory
        .load(address, bits)
        .unwrap()
        .unwrap()
        .value_u128()
        .unwrap()
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
fn adds_xn() {
    // adds x0, x1, x2
    let instruction_words = &[0xab020020];

    for ((lhs, rhs), (n, z, c, v)) in [
        ((0xffffffffffffffffu64, 0x0000000000000001u64), (0, 1, 1, 0)),
        ((0x0000000000000000, 0x0000000000000000), (0, 1, 0, 0)),
        ((0xcf5f3a38fad546ee, 0x6bdcb93bd7ac49a5), (0, 0, 1, 0)),
        ((0x0000000000000001, 0x0000000000000002), (0, 0, 0, 0)),
        ((0x7fffffffffffffff, 0x0000000000000001), (1, 0, 0, 1)),
    ] {
        dbg!((lhs, rhs), (n, z, c, v));

        let sum = lhs.wrapping_add(rhs);
        assert_eq!(n, (0 > sum as i64) as u64);
        assert_eq!(z, (sum == 0) as u64);
        assert_eq!(c, lhs.checked_add(rhs).is_none() as u64);
        assert_eq!(v, (lhs as i64).checked_add(rhs as i64).is_none() as u64);

        // TODO: can we somehow get multiple values by one call?
        let result = get_scalar(
            instruction_words,
            vec![("x1", const_(lhs, 64)), ("x2", const_(rhs, 64))],
            Memory::new(Endian::Big),
            "x0",
        );
        assert_eq!(result.value_u64().unwrap(), sum);

        let result = get_scalar(
            instruction_words,
            vec![("x1", const_(lhs, 64)), ("x2", const_(rhs, 64))],
            Memory::new(Endian::Big),
            "n",
        );
        assert_eq!(result.value_u64().unwrap(), n);

        let result = get_scalar(
            instruction_words,
            vec![("x1", const_(lhs, 64)), ("x2", const_(rhs, 64))],
            Memory::new(Endian::Big),
            "z",
        );
        assert_eq!(result.value_u64().unwrap(), z);

        let result = get_scalar(
            instruction_words,
            vec![("x1", const_(lhs, 64)), ("x2", const_(rhs, 64))],
            Memory::new(Endian::Big),
            "c",
        );
        assert_eq!(result.value_u64().unwrap(), c);

        let result = get_scalar(
            instruction_words,
            vec![("x1", const_(lhs, 64)), ("x2", const_(rhs, 64))],
            Memory::new(Endian::Big),
            "v",
        );
        assert_eq!(result.value_u64().unwrap(), v);
    }
}

#[test]
fn ldp_xn_xn() {
    let mut memory = Memory::new(Endian::Big);
    memory
        .store(0xeed85f2300, const_(0xdeadbeef12345678, 64))
        .unwrap();
    memory
        .store(0xeed85f2308, const_(0xfa5c9e60ce124c27, 64))
        .unwrap();

    // ldp x15, x3, [x9]
    let instruction_words = &[0xa9400d2f];

    // TODO: can we somehow get multiple values by one call?
    let result = get_scalar(
        instruction_words,
        vec![("x9", const_(0xeed85f2300, 64))],
        memory.clone(),
        "x15",
    );
    assert_eq!(result.value_u64().unwrap(), 0xdeadbeef12345678);

    let result = get_scalar(
        instruction_words,
        vec![("x9", const_(0xeed85f2300, 64))],
        memory,
        "x3",
    );
    assert_eq!(result.value_u64().unwrap(), 0xfa5c9e60ce124c27);
}

#[test]
fn ldp_wn_wn() {
    let mut memory = Memory::new(Endian::Big);
    memory
        .store(0xeed85f2300, const_(0xdeadbeef12345678, 64))
        .unwrap();

    // ldp w15, w3, [x9]
    let instruction_words = &[0x29400d2f];

    // TODO: can we somehow get multiple values by one call?
    let result = get_scalar(
        instruction_words,
        vec![("x9", const_(0xeed85f2300, 64))],
        memory.clone(),
        "x15",
    );
    assert_eq!(result.value_u64().unwrap(), 0xdeadbeef);

    let result = get_scalar(
        instruction_words,
        vec![("x9", const_(0xeed85f2300, 64))],
        memory,
        "x3",
    );
    assert_eq!(result.value_u64().unwrap(), 0x12345678);
}

#[test]
fn ldpsw_xn_xn() {
    let mut memory = Memory::new(Endian::Big);
    memory
        .store(0xeed85f2300, const_(0xdeadbeef12345678, 64))
        .unwrap();
    memory
        .store(0xeed85f2308, const_(0xfa5c9e60ce124c27, 64))
        .unwrap();

    // ldpsw x15, x3, [x9]
    let instruction_words = &[0x69400d2f];

    // TODO: can we somehow get multiple values by one call?
    let result = get_scalar(
        instruction_words,
        vec![("x9", const_(0xeed85f2300, 64))],
        memory.clone(),
        "x15",
    );
    assert_eq!(result.value_u64().unwrap(), 0xffffffffdeadbeef);

    let result = get_scalar(
        instruction_words,
        vec![("x9", const_(0xeed85f2300, 64))],
        memory,
        "x3",
    );
    assert_eq!(result.value_u64().unwrap(), 0x12345678);
}

#[test]
fn ldr_xn_xn() {
    let mut memory = Memory::new(Endian::Big);
    memory
        .store(0xeed85f2300, const_(0xdeadbeef12345678, 64))
        .unwrap();

    // ldr x15, [x9]
    let instruction_words = &[0xf940012f];

    let result = get_scalar(
        instruction_words,
        vec![("x9", const_(0xeed85f2300, 64))],
        memory,
        "x15",
    );
    assert_eq!(result.value_u64().unwrap(), 0xdeadbeef12345678);
}

#[test]
fn ldr_wn_xn() {
    let mut memory = Memory::new(Endian::Big);
    memory
        .store(0xeed85f2300, const_(0xdeadbeef12345678, 64))
        .unwrap();

    // ldr w15, [x9]
    let instruction_words = &[0xb940012f];

    let result = get_scalar(
        instruction_words,
        vec![("x9", const_(0xeed85f2300, 64))],
        memory,
        "x15",
    );
    assert_eq!(result.value_u64().unwrap(), 0xdeadbeef);
}

#[test]
fn ldrh_wn_xn() {
    let mut memory = Memory::new(Endian::Big);
    memory
        .store(0xeed85f2300, const_(0xdeadbeef12345678, 64))
        .unwrap();

    // ldrh w15, [x9]
    let instruction_words = &[0x7940012f];

    let result = get_scalar(
        instruction_words,
        vec![("x9", const_(0xeed85f2300, 64))],
        memory,
        "x15",
    );
    assert_eq!(result.value_u64().unwrap(), 0xdead);
}

#[test]
fn ldrb_wn_xn() {
    let mut memory = Memory::new(Endian::Big);
    memory
        .store(0xeed85f2300, const_(0xdeadbeef12345678, 64))
        .unwrap();

    // ldrb w15, [x9]
    let instruction_words = &[0x3940012f];

    let result = get_scalar(
        instruction_words,
        vec![("x9", const_(0xeed85f2300, 64))],
        memory,
        "x15",
    );
    assert_eq!(result.value_u64().unwrap(), 0xde);
}

#[test]
fn ldr_xn_xn_preindex() {
    let mut memory = Memory::new(Endian::Big);
    memory
        .store(0xeed85f2300, const_(0xdeadbeef12345678, 64))
        .unwrap();
    memory
        .store(0xeed85f2308, const_(0x542fbb5cf6b74d14, 64))
        .unwrap();

    // ldr x15, [x9, #8]
    let instruction_words = &[0xf940052f];

    // TODO: can we somehow get multiple values by one call?
    let result = get_scalar(
        instruction_words,
        vec![("x9", const_(0xeed85f2300, 64))],
        memory.clone(),
        "x15",
    );
    assert_eq!(result.value_u64().unwrap(), 0x542fbb5cf6b74d14);

    let result = get_scalar(
        instruction_words,
        vec![("x9", const_(0xeed85f2300, 64))],
        memory,
        "x9",
    );
    assert_eq!(result.value_u64().unwrap(), 0xeed85f2300);
}

#[test]
fn ldr_xn_xn_preindex_wb() {
    let mut memory = Memory::new(Endian::Big);
    memory
        .store(0xeed85f2300, const_(0xdeadbeef12345678, 64))
        .unwrap();
    memory
        .store(0xeed85f2308, const_(0x542fbb5cf6b74d14, 64))
        .unwrap();

    // ldr x15, [x9, #8]!
    let instruction_words = &[0xf8408d2f];

    let result = get_scalar(
        instruction_words,
        vec![("x9", const_(0xeed85f2300, 64))],
        memory.clone(),
        "x15",
    );
    assert_eq!(result.value_u64().unwrap(), 0x542fbb5cf6b74d14);

    let result = get_scalar(
        instruction_words,
        vec![("x9", const_(0xeed85f2300, 64))],
        memory,
        "x9",
    );
    assert_eq!(result.value_u64().unwrap(), 0xeed85f2308);
}

#[test]
fn ldr_xn_xn_postindex_wb() {
    let mut memory = Memory::new(Endian::Big);
    memory
        .store(0xeed85f2300, const_(0xdeadbeef12345678, 64))
        .unwrap();
    memory
        .store(0xeed85f2308, const_(0x542fbb5cf6b74d14, 64))
        .unwrap();

    // ldr x15, [x9], #8
    let instruction_words = &[0xf840852f];

    let result = get_scalar(
        instruction_words,
        vec![("x9", const_(0xeed85f2300, 64))],
        memory.clone(),
        "x15",
    );
    assert_eq!(result.value_u64().unwrap(), 0xdeadbeef12345678);

    let result = get_scalar(
        instruction_words,
        vec![("x9", const_(0xeed85f2300, 64))],
        memory,
        "x9",
    );
    assert_eq!(result.value_u64().unwrap(), 0xeed85f2308);
}

#[test]
fn ldr_qn_xn() {
    let mut memory = Memory::new(Endian::Big);
    memory
        .store(0xeed85f2300, const_(0xdeadbeef12345678, 64))
        .unwrap();
    memory
        .store(0xeed85f2308, const_(0x542fbb5cf6b74d14, 64))
        .unwrap();

    // ldr q15, [x9]
    let instruction_words = &[0x3dc0012f];

    let result = get_scalar(
        instruction_words,
        vec![("x9", const_(0xeed85f2300, 64))],
        memory,
        "v15",
    );
    assert_eq!(
        result.value_u128().unwrap(),
        0xdead_beef_1234_5678_542f_bb5c_f6b7_4d14
    );
}

#[test]
fn ldr_xn_xn_xn_shift() {
    let mut memory = Memory::new(Endian::Big);
    memory
        .store(0xeed85f2300 + (3 << 3), const_(0xdeadbeef12345678, 64))
        .unwrap();

    // ldr x15, [x9, x8, lsl #3]
    let instruction_words = &[0xf868792f];

    let result = get_scalar(
        instruction_words,
        vec![("x9", const_(0xeed85f2300, 64)), ("x8", const_(3, 64))],
        memory,
        "x15",
    );
    assert_eq!(result.value_u64().unwrap(), 0xdeadbeef12345678);
}

#[test]
fn ldr_xn_xn_wn_sxtw() {
    let mut memory = Memory::new(Endian::Big);
    memory
        .store(0xeed85f2300 - 16, const_(0xdeadbeef12345678, 64))
        .unwrap();

    // ldr x15, [x9, w8, sxtw]
    let instruction_words = &[0xf868c92f];

    let result = get_scalar(
        instruction_words,
        vec![
            ("x9", const_(0xeed85f2300, 64)),
            ("x8", const_((-16i32) as u32 as _, 64)),
        ],
        memory,
        "x15",
    );
    assert_eq!(result.value_u64().unwrap(), 0xdeadbeef12345678);
}

#[test]
fn ldr_xn_xn_wn_sxtw_shift() {
    let mut memory = Memory::new(Endian::Big);
    memory
        .store(0xeed85f2300 - (1 << 3), const_(0xdeadbeef12345678, 64))
        .unwrap();

    // ldr x15, [x9, w8, sxtw #3]
    let instruction_words = &[0xf868d92f];

    let result = get_scalar(
        instruction_words,
        vec![
            ("x9", const_(0xeed85f2300, 64)),
            ("x8", const_((-1i32) as u32 as _, 64)),
        ],
        memory,
        "x15",
    );
    assert_eq!(result.value_u64().unwrap(), 0xdeadbeef12345678);
}

#[test]
fn ldr_xn_xn_wn_uxtw_shift() {
    let mut memory = Memory::new(Endian::Big);
    memory
        .store(
            0xeed85f2300 + (((-1i32) as u32 as u64) << 3),
            const_(0xdeadbeef12345678, 64),
        )
        .unwrap();

    // ldr x15, [x9, w8, uxtw #3]
    let instruction_words = &[0xf868592f];

    let result = get_scalar(
        instruction_words,
        vec![
            ("x9", const_(0xeed85f2300, 64)),
            ("x8", const_((-1i32) as u32 as _, 64)),
        ],
        memory,
        "x15",
    );
    assert_eq!(result.value_u64().unwrap(), 0xdeadbeef12345678);
}

#[test]
fn ldrsw_xn_xn() {
    let mut memory = Memory::new(Endian::Big);
    memory
        .store(0xeed85f2300, const_(0xdeadbeef12345678, 64))
        .unwrap();

    // ldrsw x15, [x9]
    let instruction_words = &[0xb980012f];

    let result = get_scalar(
        instruction_words,
        vec![("x9", const_(0xeed85f2300, 64))],
        memory,
        "x15",
    );
    assert_eq!(result.value_u64().unwrap(), 0xffffffffdeadbeef);
}

#[test]
fn ldrsh_xn_xn() {
    let mut memory = Memory::new(Endian::Big);
    memory
        .store(0xeed85f2300, const_(0xdeadbeef12345678, 64))
        .unwrap();

    // ldrsh x15, [x9]
    let instruction_words = &[0x7980012f];

    let result = get_scalar(
        instruction_words,
        vec![("x9", const_(0xeed85f2300, 64))],
        memory,
        "x15",
    );
    assert_eq!(result.value_u64().unwrap(), 0xffffffffffffdead);
}

#[test]
fn ldrsb_xn_xn() {
    let mut memory = Memory::new(Endian::Big);
    memory
        .store(0xeed85f2300, const_(0xdeadbeef12345678, 64))
        .unwrap();

    // ldrsb x15, [x9]
    let instruction_words = &[0x3980012f];

    let result = get_scalar(
        instruction_words,
        vec![("x9", const_(0xeed85f2300, 64))],
        memory,
        "x15",
    );
    assert_eq!(result.value_u64().unwrap(), 0xffffffffffffffde);
}

#[test]
fn ldrsh_wn_xn() {
    let mut memory = Memory::new(Endian::Big);
    memory
        .store(0xeed85f2300, const_(0xdeadbeef12345678, 64))
        .unwrap();

    // ldrsh w15, [x9]
    let instruction_words = &[0x79c0012f];

    let result = get_scalar(
        instruction_words,
        vec![("x9", const_(0xeed85f2300, 64))],
        memory,
        "x15",
    );
    assert_eq!(result.value_u64().unwrap(), 0xffffdead);
}

#[test]
fn ldrsb_wn_xn() {
    let mut memory = Memory::new(Endian::Big);
    memory
        .store(0xeed85f2300, const_(0xdeadbeef12345678, 64))
        .unwrap();

    // ldrsb w15, [x9]
    let instruction_words = &[0x39c0012f];

    let result = get_scalar(
        instruction_words,
        vec![("x9", const_(0xeed85f2300, 64))],
        memory,
        "x15",
    );
    assert_eq!(result.value_u64().unwrap(), 0xffffffde);
}

#[test]
fn ldur_xn_xn() {
    let mut memory = Memory::new(Endian::Big);
    memory
        .store(0xeed85f2300 + 3, const_(0xdeadbeef12345678, 64))
        .unwrap();

    // ldur x15, [x9, #3]
    let instruction_words = &[0xf840312f];

    let result = get_scalar(
        instruction_words,
        vec![("x9", const_(0xeed85f2300, 64))],
        memory,
        "x15",
    );
    assert_eq!(result.value_u64().unwrap(), 0xdeadbeef12345678);
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
fn b_cc() {
    #[allow(unused_variables)]
    let conds: [(u32, fn([u64; 4]) -> bool); 16] = [
        (0b0000, |[n, z, c, v]| z == 1),              // EQ
        (0b0001, |[n, z, c, v]| z == 0),              // NE
        (0b0010, |[n, z, c, v]| c == 1),              // CS or HS
        (0b0011, |[n, z, c, v]| c == 0),              // CC or LO
        (0b0100, |[n, z, c, v]| n == 1),              // MI
        (0b0101, |[n, z, c, v]| n == 0),              // PL
        (0b0110, |[n, z, c, v]| v == 1),              // VS
        (0b0111, |[n, z, c, v]| v == 0),              // VC
        (0b1000, |[n, z, c, v]| c == 1 && z == 0),    // HI
        (0b1001, |[n, z, c, v]| !(c == 1 && z == 0)), // LS
        (0b1010, |[n, z, c, v]| n == v),              // GE
        (0b1011, |[n, z, c, v]| n != v),              // LT
        (0b1100, |[n, z, c, v]| z == 0 && n == v),    // GT
        (0b1101, |[n, z, c, v]| !(z == 0 && n == v)), // LE
        (0b1110, |[n, z, c, v]| true),                // AL
        (0b1111, |[n, z, c, v]| true),                // NV
    ];

    for (cond, cond_fn) in conds {
        for nzcv in 0..16 {
            let [n, z, c, v] = [
                ((nzcv & 0b0001) != 0) as u64,
                ((nzcv & 0b0010) != 0) as u64,
                ((nzcv & 0b0100) != 0) as u64,
                ((nzcv & 0b1000) != 0) as u64,
            ];

            let expected = cond_fn([n, z, c, v]);

            println!(
                "[n,z,c,v] = {:?}, cond = {:#06b}, expected = {:?}",
                [n, z, c, v],
                cond,
                expected
            );

            //   mov x0, #45
            //   b.XX 1f
            //   mov x0, #44
            // 1:
            let instruction_words = &[0xd28005a0, 0x54000040 | cond, 0xd2800580];

            let result = get_scalar(
                instruction_words,
                vec![
                    ("n", const_(n, 1)),
                    ("z", const_(z, 1)),
                    ("c", const_(c, 1)),
                    ("v", const_(v, 1)),
                ],
                Memory::new(Endian::Big),
                "x0",
            );

            assert_eq!(result.value_u64().unwrap(), [44, 45][expected as usize]);
        }
    }
}

#[test]
fn bl_ret() {
    //    mov x25, #1
    //    bl 0f
    //    add x25, x25, #8
    //    nop
    //  0:
    //    mov x25, #2
    //    ret
    let instruction_words =
        backing!(&[0xd2800039, 0x94000003, 0x91002339, 0xd503201f, 0xd2800059, 0xd65f03c0]);

    let driver = init_driver_function(instruction_words, vec![("x25", const_(42, 64))]);

    let driver = step_to(driver, 0xc);

    assert_eq!(
        driver
            .state()
            .get_scalar("x25")
            .unwrap()
            .value_u64()
            .unwrap(),
        10
    );
    assert_eq!(
        driver
            .state()
            .get_scalar("x30")
            .unwrap()
            .value_u64()
            .unwrap(),
        8
    );
}

#[test]
fn blr() {
    //   blr x1
    //   mov x3, #2
    // 1:
    //   add x3, x3, #4
    let instruction_words = &[0xd63f0020, 0xd2800043, 0x91001063];

    let result = get_scalar(
        instruction_words,
        vec![
            ("x1", const_(8, 64)),
            ("x3", const_(1, 64)),
            ("x30", const_(4, 64)),
        ],
        Memory::new(Endian::Big),
        "x3",
    );
    assert_eq!(result.value_u64().unwrap(), 5);
}

#[test]
fn br() {
    //   br x1
    //   mov x3, #2
    // 1:
    //   add x3, x3, #4
    //   nop
    let instruction_words = &[0xd61f0020, 0xd2800043, 0x91001063, 0xd503201f];

    let driver = init_driver_function(
        backing!(instruction_words),
        vec![("x1", const_(8, 64)), ("x3", const_(1, 64))],
    );
    let driver = step_to(driver, 0xc);

    assert_eq!(
        driver
            .state()
            .get_scalar("x3")
            .unwrap()
            .value_u64()
            .unwrap(),
        5
    );
}

#[test]
fn cbnz() {
    //   mov x0, #45
    //   cbnz x4, 1f
    //   mov x0, #44
    // 1:
    let instruction_words = &[0xd28005a0, 0xb5000044, 0xd2800580];

    let result = get_scalar(
        instruction_words,
        vec![("x4", const_(0, 64))],
        Memory::new(Endian::Big),
        "x0",
    );
    assert_eq!(result.value_u64().unwrap(), 44);

    let result = get_scalar(
        instruction_words,
        vec![("x4", const_(!0u64, 64))],
        Memory::new(Endian::Big),
        "x0",
    );
    assert_eq!(result.value_u64().unwrap(), 45);
}

#[test]
fn cbz() {
    //   mov x0, #45
    //   cbz x4, 1f
    //   mov x0, #44
    // 1:
    let instruction_words = &[0xd28005a0, 0xb4000044, 0xd2800580];

    let result = get_scalar(
        instruction_words,
        vec![("x4", const_(0, 64))],
        Memory::new(Endian::Big),
        "x0",
    );
    assert_eq!(result.value_u64().unwrap(), 45);

    let result = get_scalar(
        instruction_words,
        vec![("x4", const_(!0u64, 64))],
        Memory::new(Endian::Big),
        "x0",
    );
    assert_eq!(result.value_u64().unwrap(), 44);
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
fn stp_xn_xn() {
    // stp x15, x28, [x9]; nop
    let instruction_words = &[0xa900712f, 0xd503201f];

    let driver = init_driver_function(
        backing!(instruction_words),
        vec![
            ("x15", const_(0xdeadbeef12345678, 64)),
            ("x28", const_(0x5d90e16ef8ea43ce, 64)),
            ("x9", const_(0xeed85f2300, 64)),
        ],
    );
    let driver = step_to(driver, 0x4);

    let memory = driver.state().memory();
    assert_eq!(memval(memory, 0xeed85f2300, 64), 0xdeadbeef12345678);
    assert_eq!(memval(memory, 0xeed85f2308, 64), 0x5d90e16ef8ea43ce);
}

#[test]
fn stp_wn_wn() {
    // stp w15, w28, [x9]; nop
    let instruction_words = &[0x2900712f, 0xd503201f];

    let driver = init_driver_function(
        backing!(instruction_words),
        vec![
            ("x15", const_(0xdeadbeef12345678, 64)),
            ("x28", const_(0x5d90e16ef8ea43ce, 64)),
            ("x9", const_(0xeed85f2300, 64)),
        ],
    );
    let driver = step_to(driver, 0x4);

    let memory = driver.state().memory();
    assert_eq!(memval(memory, 0xeed85f2300, 64), 0x12345678f8ea43ce);
}

#[test]
fn str_xn_xn() {
    // str x15, [x9]; nop
    let instruction_words = &[0xf900012f, 0xd503201f];

    let driver = init_driver_function(
        backing!(instruction_words),
        vec![
            ("x15", const_(0xdeadbeef12345678, 64)),
            ("x9", const_(0xeed85f2300, 64)),
        ],
    );
    let driver = step_to(driver, 0x4);

    let memory = driver.state().memory();
    assert_eq!(memval(memory, 0xeed85f2300, 64), 0xdeadbeef12345678);
}

#[test]
fn str_wn_xn() {
    // str xzr, [x9]; str w15, [x9]; nop
    let instruction_words = &[0xf900013f, 0xb900012f, 0xd503201f];

    let driver = init_driver_function(
        backing!(instruction_words),
        vec![
            ("x15", const_(0xdeadbeef12345678, 64)),
            ("x9", const_(0xeed85f2300, 64)),
        ],
    );
    let driver = step_to(driver, 0x8);

    let memory = driver.state().memory();
    assert_eq!(memval(memory, 0xeed85f2300, 64), 0x1234_5678_0000_0000);
}

#[test]
fn strb_wn_xn() {
    // str xzr, [x9]; strb w15, [x9]; nop
    let instruction_words = &[0xf900013f, 0x3900012f, 0xd503201f];

    let driver = init_driver_function(
        backing!(instruction_words),
        vec![
            ("x15", const_(0xdeadbeef12345678, 64)),
            ("x9", const_(0xeed85f2300, 64)),
        ],
    );
    let driver = step_to(driver, 0x8);

    let memory = driver.state().memory();
    assert_eq!(memval(memory, 0xeed85f2300, 64), 0x7800_0000_0000_0000);
}

#[test]
fn strh_wn_xn() {
    // str xzr, [x9]; strh w15, [x9]; nop
    let instruction_words = &[0xf900013f, 0x7900012f, 0xd503201f];

    let driver = init_driver_function(
        backing!(instruction_words),
        vec![
            ("x15", const_(0xdeadbeef12345678, 64)),
            ("x9", const_(0xeed85f2300, 64)),
        ],
    );
    let driver = step_to(driver, 0x8);

    let memory = driver.state().memory();
    assert_eq!(memval(memory, 0xeed85f2300, 64), 0x5678_0000_0000_0000);
}

#[test]
fn stur_wn_xn() {
    // stur xzr, [x9, #3]; stur w15, [x9, #3]; nop
    let instruction_words = &[0xf800313f, 0xb800312f, 0xd503201f];

    let driver = init_driver_function(
        backing!(instruction_words),
        vec![
            ("x15", const_(0xdeadbeef12345678, 64)),
            ("x9", const_(0xeed85f2300, 64)),
        ],
    );
    let driver = step_to(driver, 0x8);

    let memory = driver.state().memory();
    assert_eq!(memval(memory, 0xeed85f2300 + 3, 64), 0x1234_5678_0000_0000);
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

#[test]
fn subs_xn() {
    // subs x0, x1, x2
    let instruction_words = &[0xeb020020];

    for ((lhs, rhs), (n, z, c, v)) in [
        ((0xffffffffffffffffu64, 0x0000000000000001u64), (1, 0, 0, 0)),
        ((0x0000000000000000, 0x0000000000000000), (0, 1, 0, 0)),
        ((0xcf5f3a38fad546ee, 0x6bdcb93bd7ac49a5), (0, 0, 0, 1)),
        ((0x0000000000000001, 0x0000000000000002), (1, 0, 1, 0)),
    ] {
        dbg!((lhs, rhs), (n, z, c, v));

        let sum = lhs.wrapping_sub(rhs);
        assert_eq!(n, (0 > sum as i64) as u64);
        assert_eq!(z, (sum == 0) as u64);
        assert_eq!(c, lhs.checked_sub(rhs).is_none() as u64);
        assert_eq!(v, (lhs as i64).checked_sub(rhs as i64).is_none() as u64);

        // TODO: can we somehow get multiple values by one call?
        let result = get_scalar(
            instruction_words,
            vec![("x1", const_(lhs, 64)), ("x2", const_(rhs, 64))],
            Memory::new(Endian::Big),
            "x0",
        );
        assert_eq!(result.value_u64().unwrap(), sum);

        let result = get_scalar(
            instruction_words,
            vec![("x1", const_(lhs, 64)), ("x2", const_(rhs, 64))],
            Memory::new(Endian::Big),
            "n",
        );
        assert_eq!(result.value_u64().unwrap(), n);

        let result = get_scalar(
            instruction_words,
            vec![("x1", const_(lhs, 64)), ("x2", const_(rhs, 64))],
            Memory::new(Endian::Big),
            "z",
        );
        assert_eq!(result.value_u64().unwrap(), z);

        let result = get_scalar(
            instruction_words,
            vec![("x1", const_(lhs, 64)), ("x2", const_(rhs, 64))],
            Memory::new(Endian::Big),
            "c",
        );
        assert_eq!(result.value_u64().unwrap(), c);

        let result = get_scalar(
            instruction_words,
            vec![("x1", const_(lhs, 64)), ("x2", const_(rhs, 64))],
            Memory::new(Endian::Big),
            "v",
        );
        assert_eq!(result.value_u64().unwrap(), v);
    }
}

#[test]
fn str_qn_xn() {
    // str q15, [x9]; nop
    let instruction_words = &[0x3d80012f, 0xd503201f];

    let driver = init_driver_function(
        backing!(instruction_words),
        vec![
            ("v15", const_(0xdeadbeef12345678, 128)),
            ("x9", const_(0xeed85f2300, 64)),
        ],
    );
    let driver = step_to(driver, 0x4);

    let memory = driver.state().memory();
    assert_eq!(memval(memory, 0xeed85f2300, 128), 0xdeadbeef12345678);
}

#[test]
fn tbnz() {
    //   mov x0, #45
    //   tbnz x4, #16, 1f
    //   mov x0, #44
    // 1:
    let instruction_words = &[0xd28005a0, 0x37800044, 0xd2800580];

    let result = get_scalar(
        instruction_words,
        vec![("x4", const_(0xdeacbeef, 64))],
        Memory::new(Endian::Big),
        "x0",
    );
    assert_eq!(result.value_u64().unwrap(), 44);

    let result = get_scalar(
        instruction_words,
        vec![("x4", const_(0xdeadbeef, 64))],
        Memory::new(Endian::Big),
        "x0",
    );
    assert_eq!(result.value_u64().unwrap(), 45);
}

#[test]
fn tbz() {
    //   mov x0, #45
    //   tbz w4, #16, 1f
    //   mov x0, #44
    // 1:
    let instruction_words = &[0xd28005a0, 0x36800044, 0xd2800580];

    let result = get_scalar(
        instruction_words,
        vec![("x4", const_(0xdeacbeef, 64))],
        Memory::new(Endian::Big),
        "x0",
    );
    assert_eq!(result.value_u64().unwrap(), 45);

    let result = get_scalar(
        instruction_words,
        vec![("x4", const_(0xdeadbeef, 64))],
        Memory::new(Endian::Big),
        "x0",
    );
    assert_eq!(result.value_u64().unwrap(), 44);
}

// TODO: rest of the instructions
