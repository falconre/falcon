use super::*;

// Known bug: In translator.rs (lines 105-106), X86_INS_BTR dispatches to
// semantics.bts() and X86_INS_BTS dispatches to semantics.btr(). They are
// swapped. These tests assert correct AMD64 manual behavior for BTS
// (bit test and set), so they will fail due to the dispatch swap -- the
// lifter will actually execute BTR semantics (bit test and reset) instead.

/// BTS rax, rbx: set a bit that is clear.
/// rax = 0xFF00 (bits 8-15 set), rbx = 3 (bit 3 is clear).
/// Per AMD64 manual: CF = original bit (0), then set bit 3 to 1.
/// Result: rax = 0xFF00 | (1 << 3) = 0xFF08.
#[test]
fn bts_set_clear_bit() {
    // bts rax, rbx; nop
    let bytes: Vec<u8> = vec![0x48, 0x0f, 0xab, 0xd8, 0x90];

    let driver = init_amd64_driver(
        bytes,
        vec![("rax", il::const_(0xFF00, 64)), ("rbx", il::const_(3, 64))],
        Memory::new(Endian::Little),
    );

    let driver = step_to(driver, 0x4);

    // CF should be 0 because the original bit was clear
    assert_flag(&driver, "CF", 0);
    // BTS should set bit 3, giving 0xFF08.
    // Due to the known BTR/BTS swap bug, this will fail: the lifter runs
    // BTR semantics (clear the bit), so rax stays 0xFF00 (bit was already 0,
    // clearing it is a no-op).
    assert_scalar(&driver, "rax", 0xFF08);
}

/// BTS rax, rbx: set a bit that is already set.
/// rax = 0xFF00 (bits 8-15 set), rbx = 10 (bit 10 is set).
/// Per AMD64 manual: CF = original bit (1), bit remains 1, dest unchanged.
/// Result: rax = 0xFF00.
#[test]
fn bts_set_already_set_bit() {
    // bts rax, rbx; nop
    let bytes: Vec<u8> = vec![0x48, 0x0f, 0xab, 0xd8, 0x90];

    let driver = init_amd64_driver(
        bytes,
        vec![("rax", il::const_(0xFF00, 64)), ("rbx", il::const_(10, 64))],
        Memory::new(Endian::Little),
    );

    let driver = step_to(driver, 0x4);

    // CF should be 1 because the original bit was set
    assert_flag(&driver, "CF", 1);
    // BTS on an already-set bit should leave dest unchanged at 0xFF00.
    // Due to the known BTR/BTS swap bug, this will fail: the lifter runs
    // BTR semantics (clear the bit), so rax becomes 0xFF00 & ~(1<<10) = 0xFB00.
    assert_scalar(&driver, "rax", 0xFF00);
}
