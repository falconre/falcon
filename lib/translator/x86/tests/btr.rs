use super::*;

// Known bug: In translator.rs (lines 105-106), X86_INS_BTR dispatches to
// semantics.bts() and X86_INS_BTS dispatches to semantics.btr(). They are
// swapped. These tests assert correct AMD64 manual behavior for BTR
// (bit test and reset), so they will fail due to the dispatch swap -- the
// lifter will actually execute BTS semantics (bit test and set) instead.

/// BTR rax, rbx: reset a bit that is set.
/// rax = 0xFF00 (bits 8-15 set), rbx = 10 (bit 10 is set).
/// Per AMD64 manual: CF = original bit (1), then clear bit 10 to 0.
/// Result: rax = 0xFF00 & ~(1 << 10) = 0xFF00 & ~0x400 = 0xFB00.
#[test]
fn btr_reset_set_bit() {
    // btr rax, rbx; nop
    let bytes: Vec<u8> = vec![0x48, 0x0f, 0xb3, 0xd8, 0x90];

    let driver = init_amd64_driver(
        bytes,
        vec![
            ("rax", il::const_(0xFF00, 64)),
            ("rbx", il::const_(10, 64)),
        ],
        Memory::new(Endian::Little),
    );

    let driver = step_to(driver, 0x4);

    // CF should be 1 because the original bit was set
    assert_flag(&driver, "CF", 1);
    // BTR should clear bit 10, giving 0xFB00
    // Due to the known BTR/BTS swap bug, this will fail: the lifter runs
    // BTS semantics (set the bit) instead of BTR (reset the bit), so rax
    // stays 0xFF00 (bit was already set, OR with it is a no-op).
    assert_scalar(&driver, "rax", 0xFB00);
}

/// BTR rax, rbx: reset a bit that is already clear.
/// rax = 0xFF00 (bits 8-15 set), rbx = 3 (bit 3 is clear).
/// Per AMD64 manual: CF = original bit (0), bit remains 0, dest unchanged.
/// Result: rax = 0xFF00.
#[test]
fn btr_reset_clear_bit() {
    // btr rax, rbx; nop
    let bytes: Vec<u8> = vec![0x48, 0x0f, 0xb3, 0xd8, 0x90];

    let driver = init_amd64_driver(
        bytes,
        vec![
            ("rax", il::const_(0xFF00, 64)),
            ("rbx", il::const_(3, 64)),
        ],
        Memory::new(Endian::Little),
    );

    let driver = step_to(driver, 0x4);

    // CF should be 0 because the original bit was clear
    assert_flag(&driver, "CF", 0);
    // BTR on an already-clear bit should leave dest unchanged at 0xFF00.
    // Due to the known BTR/BTS swap bug, this will fail: the lifter runs
    // BTS semantics (set the bit), so rax becomes 0xFF00 | (1 << 3) = 0xFF08.
    assert_scalar(&driver, "rax", 0xFF00);
}
