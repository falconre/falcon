use super::*;

/// SCASW with matching word: compares AX with [RDI], sets ZF=1.
/// Per AMD64 manual: SCASW computes AX - [RDI] (16-bit comparison) and sets flags.
/// If DF=0, RDI is incremented by 2 (word size).
/// AX = [RDI] = 0x1234: result is 0, ZF=1, CF=0, SF=0, OF=0.
/// scasw = 0x66, 0xaf.
#[test]
fn scasw_match() {
    // scasw  =>  66 af
    // nop    =>  90
    let bytes: Vec<u8> = vec![0x66, 0xaf, 0x90];

    let driver = init_amd64_driver_with_memory(
        bytes,
        vec![
            ("rdi", il::const_(0x3000, 64)),
            ("rax", il::const_(0x1234, 64)),
            ("DF", il::const_(0, 1)),
        ],
        vec![(0x3000, il::const_(0x1234, 16))],
    );

    let driver = step_to(driver, 0x2);

    // ZF=1 because AX equals word at [RDI]
    assert_flag(&driver, "ZF", 1);
    // CF=0 because no borrow
    assert_flag(&driver, "CF", 0);
    // SF=0 because result is zero
    assert_flag(&driver, "SF", 0);
    // OF=0 because no signed overflow
    assert_flag(&driver, "OF", 0);
    // RDI incremented by 2 (DF=0, word)
    assert_scalar(&driver, "rdi", 0x3002);
}

/// SCASW with non-matching word: AX != [RDI], sets ZF=0.
/// Per AMD64 manual: SCASW computes AX - [RDI].
/// AX=0x0001, [RDI]=0x0002: 0x0001 - 0x0002 = 0xFFFF (wraps), CF=1, SF=1.
/// Signed: 1 - 2 = -1, fits in 16-bit signed range => OF=0.
#[test]
fn scasw_no_match() {
    // scasw  =>  66 af
    // nop    =>  90
    let bytes: Vec<u8> = vec![0x66, 0xaf, 0x90];

    let driver = init_amd64_driver_with_memory(
        bytes,
        vec![
            ("rdi", il::const_(0x3000, 64)),
            ("rax", il::const_(0x0001, 64)),
            ("DF", il::const_(0, 1)),
        ],
        vec![(0x3000, il::const_(0x0002, 16))],
    );

    let driver = step_to(driver, 0x2);

    // ZF=0 because AX != [RDI]
    assert_flag(&driver, "ZF", 0);
    // CF=1 because 0x0001 < 0x0002 (unsigned borrow)
    assert_flag(&driver, "CF", 1);
    // Result 0xFFFF has bit 15 set => SF=1
    assert_flag(&driver, "SF", 1);
    // Signed: 1 - 2 = -1, no overflow => OF=0
    assert_flag(&driver, "OF", 0);
    // RDI incremented by 2 (DF=0, word)
    assert_scalar(&driver, "rdi", 0x3002);
}

/// SCASW with DF=1: RDI should be decremented by 2.
/// Per AMD64 manual: If DF=1, RDI is decremented by operand size (2 for word).
#[test]
fn scasw_df_set() {
    // scasw  =>  66 af
    // nop    =>  90
    let bytes: Vec<u8> = vec![0x66, 0xaf, 0x90];

    let driver = init_amd64_driver_with_memory(
        bytes,
        vec![
            ("rdi", il::const_(0x3010, 64)),
            ("rax", il::const_(0xBEEF, 64)),
            ("DF", il::const_(1, 1)),
        ],
        vec![(0x3010, il::const_(0xBEEF, 16))],
    );

    let driver = step_to(driver, 0x2);

    // ZF=1 because AX matches [RDI]
    assert_flag(&driver, "ZF", 1);
    // RDI decremented by 2 (DF=1)
    assert_scalar(&driver, "rdi", 0x300E);
}

/// SCASW: RAX should remain unchanged (SCAS does not modify the accumulator).
/// Per AMD64 manual: SCAS only compares; it does not store the result.
#[test]
fn scasw_rax_unchanged() {
    // scasw  =>  66 af
    // nop    =>  90
    let bytes: Vec<u8> = vec![0x66, 0xaf, 0x90];

    let driver = init_amd64_driver_with_memory(
        bytes,
        vec![
            ("rdi", il::const_(0x3000, 64)),
            ("rax", il::const_(0xDEADBEEF00001234, 64)),
            ("DF", il::const_(0, 1)),
        ],
        vec![(0x3000, il::const_(0x1234, 16))],
    );

    let driver = step_to(driver, 0x2);

    // RAX should remain unchanged
    assert_scalar(&driver, "rax", 0xDEADBEEF00001234);
}

/// SCASW: signed overflow case. AX=0x8000, [RDI]=0x0001.
/// 0x8000 - 0x0001 = 0x7FFF. No unsigned borrow => CF=0.
/// Signed: -32768 - 1 = -32769, overflows 16-bit signed range => OF=1.
/// Result 0x7FFF has bit 15 clear => SF=0.
#[test]
fn scasw_signed_overflow() {
    // scasw  =>  66 af
    // nop    =>  90
    let bytes: Vec<u8> = vec![0x66, 0xaf, 0x90];

    let driver = init_amd64_driver_with_memory(
        bytes,
        vec![
            ("rdi", il::const_(0x3000, 64)),
            ("rax", il::const_(0x8000, 64)),
            ("DF", il::const_(0, 1)),
        ],
        vec![(0x3000, il::const_(0x0001, 16))],
    );

    let driver = step_to(driver, 0x2);

    // ZF=0 because not equal
    assert_flag(&driver, "ZF", 0);
    // CF=0 because 0x8000 > 0x0001 (no unsigned borrow)
    assert_flag(&driver, "CF", 0);
    // Result 0x7FFF: bit 15 is 0 => SF=0
    assert_flag(&driver, "SF", 0);
    // Signed: -32768 - 1 = -32769, overflows [-32768,32767] => OF=1
    assert_flag(&driver, "OF", 1);
    // RDI incremented by 2
    assert_scalar(&driver, "rdi", 0x3002);
}
