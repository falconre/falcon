use super::*;

/// NEG rax: normal case.
/// NEG 0x0000000000000001 => 0xFFFFFFFFFFFFFFFF (two's complement of 1)
/// Expected flags: CF=1 (source was non-zero), OF=0, ZF=0, SF=1 (MSB set)
#[test]
fn neg_normal() {
    // neg rax; nop
    let bytes: Vec<u8> = vec![0x48, 0xf7, 0xd8, 0x90];

    let driver = init_amd64_driver(
        bytes,
        vec![("rax", il::const_(0x0000000000000001, 64))],
        Memory::new(Endian::Little),
    );

    let driver = step_to(driver, 0x3);

    assert_scalar(&driver, "rax", 0xFFFFFFFFFFFFFFFF);
    assert_flag(&driver, "CF", 1);
    assert_flag(&driver, "OF", 0);
    assert_flag(&driver, "ZF", 0);
    assert_flag(&driver, "SF", 1);
}

/// NEG rax: zero result case.
/// NEG 0x0000000000000000 => 0x0000000000000000
/// Expected flags: CF=0 (source was zero), OF=0, ZF=1, SF=0
#[test]
fn neg_zero() {
    // neg rax; nop
    let bytes: Vec<u8> = vec![0x48, 0xf7, 0xd8, 0x90];

    let driver = init_amd64_driver(
        bytes,
        vec![("rax", il::const_(0x0000000000000000, 64))],
        Memory::new(Endian::Little),
    );

    let driver = step_to(driver, 0x3);

    assert_scalar(&driver, "rax", 0x0);
    assert_flag(&driver, "CF", 0);
    assert_flag(&driver, "OF", 0);
    assert_flag(&driver, "ZF", 1);
    assert_flag(&driver, "SF", 0);
}

/// NEG rax: overflow case (negating INT64_MIN).
/// NEG 0x8000000000000000 => 0x8000000000000000 (wraps around: only case where OF=1)
/// Expected flags: CF=1 (source non-zero), OF=1 (negating MIN_INT), ZF=0, SF=1
#[test]
fn neg_overflow_min_int() {
    // neg rax; nop
    let bytes: Vec<u8> = vec![0x48, 0xf7, 0xd8, 0x90];

    let driver = init_amd64_driver(
        bytes,
        vec![("rax", il::const_(0x8000000000000000, 64))],
        Memory::new(Endian::Little),
    );

    let driver = step_to(driver, 0x3);

    assert_scalar(&driver, "rax", 0x8000000000000000);
    assert_flag(&driver, "CF", 1);
    assert_flag(&driver, "OF", 1);
    assert_flag(&driver, "ZF", 0);
    assert_flag(&driver, "SF", 1);
}
