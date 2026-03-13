use super::*;

// XADD rax, rbx => 0x48, 0x0f, 0xc1, 0xd8 (REX.W + 0F C1 /r + ModRM)
// Per AMD64 manual: temp = dest + src; src = original dest; dest = temp
// Flags: CF, OF, ZF, SF set based on the addition (same as ADD)

#[test]
fn xadd_rax_rbx_normal() {
    // xadd rax, rbx
    // nop
    let bytes: Vec<u8> = vec![0x48, 0x0f, 0xc1, 0xd8, 0x90];

    let driver = init_amd64_driver(
        bytes,
        vec![
            ("rax", il::const_(0x0000000000000010, 64)),
            ("rbx", il::const_(0x0000000000000020, 64)),
        ],
        Memory::new(Endian::Little),
    );

    let driver = step_to(driver, 0x4);

    // dest (rax) = 0x10 + 0x20 = 0x30
    assert_scalar(&driver, "rax", 0x0000000000000030);
    // src (rbx) = original dest = 0x10
    assert_scalar(&driver, "rbx", 0x0000000000000010);
    // Addition 0x10 + 0x20 = 0x30: no carry, no overflow
    assert_flag(&driver, "CF", 0);
    assert_flag(&driver, "OF", 0);
    assert_flag(&driver, "ZF", 0);
    assert_flag(&driver, "SF", 0);
}

#[test]
fn xadd_rax_rbx_zero_result() {
    // xadd rax, rbx
    // nop
    let bytes: Vec<u8> = vec![0x48, 0x0f, 0xc1, 0xd8, 0x90];

    let driver = init_amd64_driver(
        bytes,
        vec![
            ("rax", il::const_(0x0000000000000000, 64)),
            ("rbx", il::const_(0x0000000000000000, 64)),
        ],
        Memory::new(Endian::Little),
    );

    let driver = step_to(driver, 0x4);

    // dest (rax) = 0 + 0 = 0
    assert_scalar(&driver, "rax", 0x0000000000000000);
    // src (rbx) = original dest = 0
    assert_scalar(&driver, "rbx", 0x0000000000000000);
    // Addition 0 + 0 = 0
    assert_flag(&driver, "CF", 0);
    assert_flag(&driver, "OF", 0);
    // Result is zero => ZF=1
    assert_flag(&driver, "ZF", 1);
    assert_flag(&driver, "SF", 0);
}

#[test]
fn xadd_rax_rbx_signed_overflow() {
    // xadd rax, rbx
    // nop
    let bytes: Vec<u8> = vec![0x48, 0x0f, 0xc1, 0xd8, 0x90];

    let driver = init_amd64_driver(
        bytes,
        vec![
            ("rax", il::const_(0x7FFFFFFFFFFFFFFF, 64)),
            ("rbx", il::const_(0x0000000000000001, 64)),
        ],
        Memory::new(Endian::Little),
    );

    let driver = step_to(driver, 0x4);

    // dest (rax) = 0x7FFFFFFFFFFFFFFF + 1 = 0x8000000000000000
    assert_scalar(&driver, "rax", 0x8000000000000000);
    // src (rbx) = original dest = 0x7FFFFFFFFFFFFFFF
    assert_scalar(&driver, "rbx", 0x7FFFFFFFFFFFFFFF);
    // No unsigned carry (0x7FFF... + 1 fits in 64 bits) => CF=0
    assert_flag(&driver, "CF", 0);
    // Signed overflow: positive + positive = negative => OF=1
    assert_flag(&driver, "OF", 1);
    // Result is non-zero => ZF=0
    assert_flag(&driver, "ZF", 0);
    // MSB of 0x8000000000000000 is 1 => SF=1
    assert_flag(&driver, "SF", 1);
}

/// XADD rax, rbx: negative signed overflow case.
/// 0x8000000000000000 + 0x8000000000000000 = 0 (mod 2^64)
/// Two negative numbers produce a non-negative result => OF=1.
/// Unsigned carry => CF=1. Result is zero => ZF=1, SF=0.
#[test]
fn xadd_rax_rbx_negative_overflow() {
    // xadd rax, rbx
    // nop
    let bytes: Vec<u8> = vec![0x48, 0x0f, 0xc1, 0xd8, 0x90];

    let driver = init_amd64_driver(
        bytes,
        vec![
            ("rax", il::const_(0x8000000000000000, 64)),
            ("rbx", il::const_(0x8000000000000000, 64)),
        ],
        Memory::new(Endian::Little),
    );

    let driver = step_to(driver, 0x4);

    // dest (rax) = 0x8000000000000000 + 0x8000000000000000 = 0
    assert_scalar(&driver, "rax", 0x0);
    // src (rbx) = original dest = 0x8000000000000000
    assert_scalar(&driver, "rbx", 0x8000000000000000);
    // Unsigned carry => CF=1
    assert_flag(&driver, "CF", 1);
    // Signed overflow: negative + negative = non-negative => OF=1
    assert_flag(&driver, "OF", 1);
    // Result is zero => ZF=1
    assert_flag(&driver, "ZF", 1);
    // Result is 0 => SF=0
    assert_flag(&driver, "SF", 0);
}
