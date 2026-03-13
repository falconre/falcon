use super::*;

/// SBB rax, rbx: normal case with CF=0 input.
/// 0x5678 - 0x1234 - 0 = 0x4444
/// Expected flags: CF=0, OF=0, ZF=0, SF=0
#[test]
fn sbb_normal_cf_clear() {
    // sbb rax, rbx; nop
    let bytes: Vec<u8> = vec![0x48, 0x19, 0xd8, 0x90];

    let driver = init_amd64_driver(
        bytes,
        vec![
            ("rax", il::const_(0x5678, 64)),
            ("rbx", il::const_(0x1234, 64)),
            ("CF", il::const_(0, 1)),
        ],
        Memory::new(Endian::Little),
    );

    let driver = step_to(driver, 0x3);

    assert_scalar(&driver, "rax", 0x4444);
    assert_flag(&driver, "CF", 0);
    assert_flag(&driver, "OF", 0);
    assert_flag(&driver, "ZF", 0);
    assert_flag(&driver, "SF", 0);
}

/// SBB rax, rbx: zero result with CF=1 input.
/// 0x1235 - 0x1234 - 1 = 0
/// Expected flags: CF=0, OF=0, ZF=1, SF=0
#[test]
fn sbb_zero_result_with_borrow_in() {
    // sbb rax, rbx; nop
    let bytes: Vec<u8> = vec![0x48, 0x19, 0xd8, 0x90];

    let driver = init_amd64_driver(
        bytes,
        vec![
            ("rax", il::const_(0x1235, 64)),
            ("rbx", il::const_(0x1234, 64)),
            ("CF", il::const_(1, 1)),
        ],
        Memory::new(Endian::Little),
    );

    let driver = step_to(driver, 0x3);

    assert_scalar(&driver, "rax", 0x0);
    assert_flag(&driver, "CF", 0);
    assert_flag(&driver, "OF", 0);
    assert_flag(&driver, "ZF", 1);
    assert_flag(&driver, "SF", 0);
}

/// SBB rax, rbx: signed overflow triggered by borrow-in.
/// 0x8000000000000000 - 0x0000000000000000 - CF=1 = 0x7FFFFFFFFFFFFFFF
/// Most-negative minus borrow produces positive => signed overflow (OF=1).
/// No unsigned borrow (large minus zero minus one is still large unsigned) => CF=0.
/// MSB=0 => SF=0. Non-zero => ZF=0.
#[test]
fn sbb_signed_overflow_via_borrow() {
    // sbb rax, rbx; nop
    let bytes: Vec<u8> = vec![0x48, 0x19, 0xd8, 0x90];

    let driver = init_amd64_driver(
        bytes,
        vec![
            ("rax", il::const_(0x8000000000000000, 64)),
            ("rbx", il::const_(0x0000000000000000, 64)),
            ("CF", il::const_(1, 1)),
        ],
        Memory::new(Endian::Little),
    );

    let driver = step_to(driver, 0x3);

    assert_scalar(&driver, "rax", 0x7FFFFFFFFFFFFFFF);
    assert_flag(&driver, "CF", 0);
    assert_flag(&driver, "OF", 1);
    assert_flag(&driver, "ZF", 0);
    assert_flag(&driver, "SF", 0);
}

/// SBB rax, rbx: positive-direction signed overflow with CF=0.
/// 0x7FFFFFFFFFFFFFFF - 0xFFFFFFFFFFFFFFFF - 0 = 0x8000000000000000 (mod 2^64)
/// Signed: MAX_INT64 - (-1) = MAX_INT64+1, overflows positive direction => OF=1.
/// Unsigned: 0x7FFF... < 0xFFFF... => borrow => CF=1.
/// Result MSB=1 => SF=1. Non-zero => ZF=0.
#[test]
fn sbb_positive_overflow() {
    // sbb rax, rbx; nop
    let bytes: Vec<u8> = vec![0x48, 0x19, 0xd8, 0x90];

    let driver = init_amd64_driver(
        bytes,
        vec![
            ("rax", il::const_(0x7FFFFFFFFFFFFFFF, 64)),
            ("rbx", il::const_(0xFFFFFFFFFFFFFFFF, 64)),
            ("CF", il::const_(0, 1)),
        ],
        Memory::new(Endian::Little),
    );

    let driver = step_to(driver, 0x3);

    assert_scalar(&driver, "rax", 0x8000000000000000);
    assert_flag(&driver, "CF", 1);
    assert_flag(&driver, "OF", 1);
    assert_flag(&driver, "ZF", 0);
    assert_flag(&driver, "SF", 1);
}
