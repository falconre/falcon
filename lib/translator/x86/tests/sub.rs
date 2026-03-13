use super::*;

/// SUB rax, rbx: normal case, two non-zero values producing non-zero result.
/// 0x5678 - 0x1234 = 0x4444
/// Expected flags: CF=0 (no borrow), OF=0, ZF=0, SF=0
#[test]
fn sub_normal() {
    // sub rax, rbx; nop
    let bytes: Vec<u8> = vec![0x48, 0x29, 0xd8, 0x90];

    let driver = init_amd64_driver(
        bytes,
        vec![
            ("rax", il::const_(0x5678, 64)),
            ("rbx", il::const_(0x1234, 64)),
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

/// SUB rax, rbx: zero result case.
/// 0x1234 - 0x1234 = 0
/// Expected flags: CF=0 (no borrow, equal values), OF=0, ZF=1, SF=0
#[test]
fn sub_zero_result() {
    // sub rax, rbx; nop
    let bytes: Vec<u8> = vec![0x48, 0x29, 0xd8, 0x90];

    let driver = init_amd64_driver(
        bytes,
        vec![
            ("rax", il::const_(0x1234, 64)),
            ("rbx", il::const_(0x1234, 64)),
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

/// SUB rax, rbx: borrow (CF) and signed overflow (OF) case.
/// 0x8000000000000000 - 1 = 0x7FFFFFFFFFFFFFFF
/// Signed: most-negative minus positive yields positive => signed overflow (OF=1).
/// Unsigned: large value minus small => no borrow (CF=0).
/// Result MSB=0 => SF=0. Result non-zero => ZF=0.
#[test]
fn sub_signed_overflow() {
    // sub rax, rbx; nop
    let bytes: Vec<u8> = vec![0x48, 0x29, 0xd8, 0x90];

    let driver = init_amd64_driver(
        bytes,
        vec![
            ("rax", il::const_(0x8000000000000000, 64)),
            ("rbx", il::const_(0x0000000000000001, 64)),
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
