use super::*;

/// CMP rax, rbx: normal case, dest > src unsigned.
/// Computes 0x5678 - 0x1234 = 0x4444 but does NOT store result.
/// Expected: rax unchanged at 0x5678. Flags: CF=0, OF=0, ZF=0, SF=0.
#[test]
fn cmp_normal() {
    // cmp rax, rbx; nop
    let bytes: Vec<u8> = vec![0x48, 0x39, 0xd8, 0x90];

    let driver = init_amd64_driver(
        bytes,
        vec![
            ("rax", il::const_(0x5678, 64)),
            ("rbx", il::const_(0x1234, 64)),
        ],
        Memory::new(Endian::Little),
    );

    let driver = step_to(driver, 0x3);

    // CMP must NOT modify the destination operand.
    assert_scalar(&driver, "rax", 0x5678);
    // CMP must NOT modify the source operand.
    assert_scalar(&driver, "rbx", 0x1234);
    assert_flag(&driver, "CF", 0);
    assert_flag(&driver, "OF", 0);
    assert_flag(&driver, "ZF", 0);
    assert_flag(&driver, "SF", 0);
}

/// CMP rax, rbx: equal values produce zero.
/// Computes 0x1234 - 0x1234 = 0, sets ZF=1.
/// Expected: rax unchanged. Flags: CF=0, OF=0, ZF=1, SF=0.
#[test]
fn cmp_equal_zero_flag() {
    // cmp rax, rbx; nop
    let bytes: Vec<u8> = vec![0x48, 0x39, 0xd8, 0x90];

    let driver = init_amd64_driver(
        bytes,
        vec![
            ("rax", il::const_(0x1234, 64)),
            ("rbx", il::const_(0x1234, 64)),
        ],
        Memory::new(Endian::Little),
    );

    let driver = step_to(driver, 0x3);

    // CMP must NOT modify either operand.
    assert_scalar(&driver, "rax", 0x1234);
    assert_scalar(&driver, "rbx", 0x1234);
    assert_flag(&driver, "CF", 0);
    assert_flag(&driver, "OF", 0);
    assert_flag(&driver, "ZF", 1);
    assert_flag(&driver, "SF", 0);
}

/// CMP rax, rbx: borrow case, dest < src unsigned.
/// Computes 0x1 - 0x2 => wraps, CF=1 (borrow).
/// Signed: 1 - 2 = -1 => no signed overflow, SF=1.
/// Expected: rax unchanged at 0x1. Flags: CF=1, OF=0, ZF=0, SF=1.
#[test]
fn cmp_borrow() {
    // cmp rax, rbx; nop
    let bytes: Vec<u8> = vec![0x48, 0x39, 0xd8, 0x90];

    let driver = init_amd64_driver(
        bytes,
        vec![
            ("rax", il::const_(0x0000000000000001, 64)),
            ("rbx", il::const_(0x0000000000000002, 64)),
        ],
        Memory::new(Endian::Little),
    );

    let driver = step_to(driver, 0x3);

    // CMP must NOT modify either operand.
    assert_scalar(&driver, "rax", 0x0000000000000001);
    assert_scalar(&driver, "rbx", 0x0000000000000002);
    assert_flag(&driver, "CF", 1);
    assert_flag(&driver, "OF", 0);
    assert_flag(&driver, "ZF", 0);
    assert_flag(&driver, "SF", 1);
}
