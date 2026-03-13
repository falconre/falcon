use super::*;

/// ADD rax, rbx: normal case, two non-zero values producing non-zero result.
/// 0x1234 + 0x5678 = 0x68AC
/// Expected flags: CF=0, OF=0, ZF=0, SF=0
#[test]
fn add_normal() {
    // add rax, rbx; nop
    let bytes: Vec<u8> = vec![0x48, 0x01, 0xd8, 0x90];

    let driver = init_amd64_driver(
        bytes,
        vec![
            ("rax", il::const_(0x1234, 64)),
            ("rbx", il::const_(0x5678, 64)),
        ],
        Memory::new(Endian::Little),
    );

    let driver = step_to(driver, 0x3);

    assert_scalar(&driver, "rax", 0x68AC);
    assert_flag(&driver, "CF", 0);
    assert_flag(&driver, "OF", 0);
    assert_flag(&driver, "ZF", 0);
    assert_flag(&driver, "SF", 0);
}

/// ADD rax, rbx: zero result case.
/// 0x0000000000000001 + 0xFFFFFFFFFFFFFFFF = 0 (mod 2^64)
/// Expected flags: CF=1 (carry out), OF=0 (no signed overflow: pos + neg = zero), ZF=1, SF=0
#[test]
fn add_zero_result() {
    // add rax, rbx; nop
    let bytes: Vec<u8> = vec![0x48, 0x01, 0xd8, 0x90];

    let driver = init_amd64_driver(
        bytes,
        vec![
            ("rax", il::const_(0x0000000000000001, 64)),
            ("rbx", il::const_(0xFFFFFFFFFFFFFFFF, 64)),
        ],
        Memory::new(Endian::Little),
    );

    let driver = step_to(driver, 0x3);

    assert_scalar(&driver, "rax", 0x0);
    assert_flag(&driver, "CF", 1);
    assert_flag(&driver, "OF", 0);
    assert_flag(&driver, "ZF", 1);
    assert_flag(&driver, "SF", 0);
}

/// ADD rax, rbx: signed overflow case.
/// 0x7FFFFFFFFFFFFFFF + 1 = 0x8000000000000000
/// Two positive numbers produce a negative result => OF=1.
/// No unsigned carry => CF=0.
/// Result has MSB set => SF=1. Result is non-zero => ZF=0.
#[test]
fn add_signed_overflow() {
    // add rax, rbx; nop
    let bytes: Vec<u8> = vec![0x48, 0x01, 0xd8, 0x90];

    let driver = init_amd64_driver(
        bytes,
        vec![
            ("rax", il::const_(0x7FFFFFFFFFFFFFFF, 64)),
            ("rbx", il::const_(0x0000000000000001, 64)),
        ],
        Memory::new(Endian::Little),
    );

    let driver = step_to(driver, 0x3);

    assert_scalar(&driver, "rax", 0x8000000000000000);
    assert_flag(&driver, "CF", 0);
    assert_flag(&driver, "OF", 1);
    assert_flag(&driver, "ZF", 0);
    assert_flag(&driver, "SF", 1);
}

/// ADD rax, rbx: negative signed overflow case.
/// 0x8000000000000000 + 0x8000000000000000 = 0 (mod 2^64)
/// Two negative numbers produce a non-negative result => OF=1.
/// Unsigned carry => CF=1. Result is zero => ZF=1, SF=0.
#[test]
fn add_negative_overflow() {
    // add rax, rbx; nop
    let bytes: Vec<u8> = vec![0x48, 0x01, 0xd8, 0x90];

    let driver = init_amd64_driver(
        bytes,
        vec![
            ("rax", il::const_(0x8000000000000000, 64)),
            ("rbx", il::const_(0x8000000000000000, 64)),
        ],
        Memory::new(Endian::Little),
    );

    let driver = step_to(driver, 0x3);

    assert_scalar(&driver, "rax", 0x0);
    assert_flag(&driver, "CF", 1);
    assert_flag(&driver, "OF", 1);
    assert_flag(&driver, "ZF", 1);
    assert_flag(&driver, "SF", 0);
}

/// ADD rax, rbx: near boundary but no overflow.
/// 0x7FFFFFFFFFFFFFFE + 1 = 0x7FFFFFFFFFFFFFFF
/// Both positive, result still positive => OF=0.
/// No carry => CF=0. SF=0, ZF=0.
#[test]
fn add_near_boundary_no_overflow() {
    // add rax, rbx; nop
    let bytes: Vec<u8> = vec![0x48, 0x01, 0xd8, 0x90];

    let driver = init_amd64_driver(
        bytes,
        vec![
            ("rax", il::const_(0x7FFFFFFFFFFFFFFE, 64)),
            ("rbx", il::const_(0x0000000000000001, 64)),
        ],
        Memory::new(Endian::Little),
    );

    let driver = step_to(driver, 0x3);

    assert_scalar(&driver, "rax", 0x7FFFFFFFFFFFFFFF);
    assert_flag(&driver, "CF", 0);
    assert_flag(&driver, "OF", 0);
    assert_flag(&driver, "ZF", 0);
    assert_flag(&driver, "SF", 0);
}
