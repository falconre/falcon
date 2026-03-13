use super::*;

/// SCASB with matching byte: compares AL with [RDI], sets ZF=1.
/// Per AMD64 manual: SCASB computes AL - [RDI] and sets flags.
/// If DF=0, RDI is incremented by 1.
/// AL = [RDI] = 0x42: result is 0, ZF=1, CF=0, SF=0, OF=0.
/// scasb = 0xae.
#[test]
fn scasb_match() {
    // scasb  =>  ae
    // nop    =>  90
    let bytes: Vec<u8> = vec![0xae, 0x90];

    let driver = init_amd64_driver_with_memory(
        bytes,
        vec![
            ("rdi", il::const_(0x3000, 64)),
            ("rax", il::const_(0x42, 64)),
            ("DF", il::const_(0, 1)),
        ],
        vec![(0x3000, il::const_(0x42, 8))],
    );

    let driver = step_to(driver, 0x1);

    // ZF=1 because AL equals byte at [RDI]
    assert_flag(&driver, "ZF", 1);
    // CF=0 because no borrow
    assert_flag(&driver, "CF", 0);
    // SF=0 because result is zero
    assert_flag(&driver, "SF", 0);
    // OF=0 because no signed overflow
    assert_flag(&driver, "OF", 0);
    // RDI incremented by 1 (DF=0)
    assert_scalar(&driver, "rdi", 0x3001);
}

/// SCASB with non-matching byte: AL != [RDI], sets ZF=0.
/// Per AMD64 manual: SCASB computes AL - [RDI].
/// AL=0x42, [RDI]=0x43: 0x42 - 0x43 = 0xFF (wraps), CF=1, SF=1.
/// Signed: 66 - 67 = -1, fits in signed range => OF=0.
#[test]
fn scasb_no_match() {
    // scasb  =>  ae
    // nop    =>  90
    let bytes: Vec<u8> = vec![0xae, 0x90];

    let driver = init_amd64_driver_with_memory(
        bytes,
        vec![
            ("rdi", il::const_(0x3000, 64)),
            ("rax", il::const_(0x42, 64)),
            ("DF", il::const_(0, 1)),
        ],
        vec![(0x3000, il::const_(0x43, 8))],
    );

    let driver = step_to(driver, 0x1);

    // ZF=0 because AL != [RDI]
    assert_flag(&driver, "ZF", 0);
    // CF=1 because 0x42 < 0x43 (unsigned borrow)
    assert_flag(&driver, "CF", 1);
    // Result 0xFF has bit 7 set => SF=1
    assert_flag(&driver, "SF", 1);
    // Signed: 66 - 67 = -1, no overflow => OF=0
    assert_flag(&driver, "OF", 0);
    // RDI incremented by 1 (DF=0)
    assert_scalar(&driver, "rdi", 0x3001);
}

/// SCASB with DF=1: RDI should be decremented by 1.
/// Per AMD64 manual: If DF=1, RDI is decremented by operand size (1 for byte).
#[test]
fn scasb_df_set() {
    // scasb  =>  ae
    // nop    =>  90
    let bytes: Vec<u8> = vec![0xae, 0x90];

    let driver = init_amd64_driver_with_memory(
        bytes,
        vec![
            ("rdi", il::const_(0x3010, 64)),
            ("rax", il::const_(0xAA, 64)),
            ("DF", il::const_(1, 1)),
        ],
        vec![(0x3010, il::const_(0xAA, 8))],
    );

    let driver = step_to(driver, 0x1);

    // ZF=1 because AL matches [RDI]
    assert_flag(&driver, "ZF", 1);
    // RDI decremented by 1 (DF=1)
    assert_scalar(&driver, "rdi", 0x300F);
}

/// SCASB: RAX should remain unchanged (SCAS does not modify the accumulator).
/// Per AMD64 manual: SCAS only compares; it does not store the result.
#[test]
fn scasb_rax_unchanged() {
    // scasb  =>  ae
    // nop    =>  90
    let bytes: Vec<u8> = vec![0xae, 0x90];

    let driver = init_amd64_driver_with_memory(
        bytes,
        vec![
            ("rdi", il::const_(0x3000, 64)),
            ("rax", il::const_(0xDEADBEEF00000042, 64)),
            ("DF", il::const_(0, 1)),
        ],
        vec![(0x3000, il::const_(0x42, 8))],
    );

    let driver = step_to(driver, 0x1);

    // RAX should remain unchanged
    assert_scalar(&driver, "rax", 0xDEADBEEF00000042);
}

/// SCASB: AL > [RDI] case. 0x80 - 0x01 = 0x7F, no borrow.
/// Signed: -128 - 1 = -129, overflows 8-bit signed range => OF=1.
/// Result 0x7F has bit 7 clear => SF=0.
#[test]
fn scasb_al_greater() {
    // scasb  =>  ae
    // nop    =>  90
    let bytes: Vec<u8> = vec![0xae, 0x90];

    let driver = init_amd64_driver_with_memory(
        bytes,
        vec![
            ("rdi", il::const_(0x3000, 64)),
            ("rax", il::const_(0x80, 64)),
            ("DF", il::const_(0, 1)),
        ],
        vec![(0x3000, il::const_(0x01, 8))],
    );

    let driver = step_to(driver, 0x1);

    // ZF=0 because not equal
    assert_flag(&driver, "ZF", 0);
    // CF=0 because 0x80 > 0x01 (no unsigned borrow)
    assert_flag(&driver, "CF", 0);
    // Result 0x7F: bit 7 is 0 => SF=0
    assert_flag(&driver, "SF", 0);
    // Signed: -128 - 1 = -129, overflows [-128,127] => OF=1
    assert_flag(&driver, "OF", 1);
    // RDI incremented by 1
    assert_scalar(&driver, "rdi", 0x3001);
}
