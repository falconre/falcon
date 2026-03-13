use super::*;

/// BTC rax, rbx: complement a bit that is set.
/// rax = 0xFF00 (bits 8-15 set), rbx = 10 (bit 10 is set).
/// Per AMD64 manual: CF = original bit (1), then complement bit 10.
/// Result: rax = 0xFF00 ^ (1 << 10) = 0xFF00 ^ 0x400 = 0xFB00.
#[test]
fn btc_complement_set_bit() {
    // btc rax, rbx; nop
    let bytes: Vec<u8> = vec![0x48, 0x0f, 0xbb, 0xd8, 0x90];

    let driver = init_amd64_driver(
        bytes,
        vec![("rax", il::const_(0xFF00, 64)), ("rbx", il::const_(10, 64))],
        Memory::new(Endian::Little),
    );

    let driver = step_to(driver, 0x4);

    assert_flag(&driver, "CF", 1);
    assert_scalar(&driver, "rax", 0xFB00);
}

/// BTC rax, rbx: complement a bit that is clear.
/// rax = 0xFF00 (bits 8-15 set), rbx = 3 (bit 3 is clear).
/// Per AMD64 manual: CF = original bit (0), then complement bit 3.
/// Result: rax = 0xFF00 ^ (1 << 3) = 0xFF00 ^ 0x8 = 0xFF08.
#[test]
fn btc_complement_clear_bit() {
    // btc rax, rbx; nop
    let bytes: Vec<u8> = vec![0x48, 0x0f, 0xbb, 0xd8, 0x90];

    let driver = init_amd64_driver(
        bytes,
        vec![("rax", il::const_(0xFF00, 64)), ("rbx", il::const_(3, 64))],
        Memory::new(Endian::Little),
    );

    let driver = step_to(driver, 0x4);

    assert_flag(&driver, "CF", 0);
    assert_scalar(&driver, "rax", 0xFF08);
}
