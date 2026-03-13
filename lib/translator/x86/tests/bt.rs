use super::*;

/// BT rax, rbx: test a bit that is set.
/// rax = 0xFF00 (bits 8-15 set), rbx = 10 (test bit 10).
/// Bit 10 of 0xFF00 is 1, so CF = 1.
/// BT does NOT modify the destination operand.
#[test]
fn bt_bit_is_set() {
    // bt rax, rbx; nop
    let bytes: Vec<u8> = vec![0x48, 0x0f, 0xa3, 0xd8, 0x90];

    let driver = init_amd64_driver(
        bytes,
        vec![
            ("rax", il::const_(0xFF00, 64)),
            ("rbx", il::const_(10, 64)),
        ],
        Memory::new(Endian::Little),
    );

    let driver = step_to(driver, 0x4);

    assert_flag(&driver, "CF", 1);
    // BT must not modify dest
    assert_scalar(&driver, "rax", 0xFF00);
}

/// BT rax, rbx: test a bit that is clear.
/// rax = 0xFF00 (bits 8-15 set), rbx = 3 (test bit 3).
/// Bit 3 of 0xFF00 is 0, so CF = 0.
/// BT does NOT modify the destination operand.
#[test]
fn bt_bit_is_clear() {
    // bt rax, rbx; nop
    let bytes: Vec<u8> = vec![0x48, 0x0f, 0xa3, 0xd8, 0x90];

    let driver = init_amd64_driver(
        bytes,
        vec![
            ("rax", il::const_(0xFF00, 64)),
            ("rbx", il::const_(3, 64)),
        ],
        Memory::new(Endian::Little),
    );

    let driver = step_to(driver, 0x4);

    assert_flag(&driver, "CF", 0);
    // BT must not modify dest
    assert_scalar(&driver, "rax", 0xFF00);
}
