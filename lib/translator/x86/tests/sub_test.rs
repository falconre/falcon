use super::*;

/// TEST rax, rbx: normal case, non-zero AND result.
/// 0xFF00 AND 0xFF00 = 0xFF00
/// Expected: rax unchanged. Flags: CF=0, OF=0, ZF=0, SF=0.
#[test]
fn test_normal() {
    // test rax, rbx; nop
    let bytes: Vec<u8> = vec![0x48, 0x85, 0xd8, 0x90];

    let driver = init_amd64_driver(
        bytes,
        vec![
            ("rax", il::const_(0xFF00, 64)),
            ("rbx", il::const_(0xFF00, 64)),
        ],
        Memory::new(Endian::Little),
    );

    let driver = step_to(driver, 0x3);

    // TEST must NOT modify either operand.
    assert_scalar(&driver, "rax", 0xFF00);
    assert_scalar(&driver, "rbx", 0xFF00);
    assert_flag(&driver, "CF", 0);
    assert_flag(&driver, "OF", 0);
    assert_flag(&driver, "ZF", 0);
    assert_flag(&driver, "SF", 0);
}

/// TEST rax, rbx: zero result (disjoint bits).
/// 0x00FF AND 0xFF00 = 0x0000
/// Expected: rax unchanged. Flags: CF=0, OF=0, ZF=1, SF=0.
#[test]
fn test_zero_result() {
    // test rax, rbx; nop
    let bytes: Vec<u8> = vec![0x48, 0x85, 0xd8, 0x90];

    let driver = init_amd64_driver(
        bytes,
        vec![
            ("rax", il::const_(0x00FF, 64)),
            ("rbx", il::const_(0xFF00, 64)),
        ],
        Memory::new(Endian::Little),
    );

    let driver = step_to(driver, 0x3);

    // TEST must NOT modify either operand.
    assert_scalar(&driver, "rax", 0x00FF);
    assert_scalar(&driver, "rbx", 0xFF00);
    assert_flag(&driver, "CF", 0);
    assert_flag(&driver, "OF", 0);
    assert_flag(&driver, "ZF", 1);
    assert_flag(&driver, "SF", 0);
}

/// TEST rax, rbx: negative result (MSB set in AND result).
/// 0x8000000000000001 AND 0xFFFFFFFFFFFFFFFF = 0x8000000000000001
/// Expected: rax unchanged. Flags: CF=0, OF=0, ZF=0, SF=1 (MSB set).
#[test]
fn test_negative_result() {
    // test rax, rbx; nop
    let bytes: Vec<u8> = vec![0x48, 0x85, 0xd8, 0x90];

    let driver = init_amd64_driver(
        bytes,
        vec![
            ("rax", il::const_(0x8000000000000001, 64)),
            ("rbx", il::const_(0xFFFFFFFFFFFFFFFF, 64)),
        ],
        Memory::new(Endian::Little),
    );

    let driver = step_to(driver, 0x3);

    // TEST must NOT modify either operand.
    assert_scalar(&driver, "rax", 0x8000000000000001);
    assert_scalar(&driver, "rbx", 0xFFFFFFFFFFFFFFFF);
    assert_flag(&driver, "CF", 0);
    assert_flag(&driver, "OF", 0);
    assert_flag(&driver, "ZF", 0);
    assert_flag(&driver, "SF", 1);
}
