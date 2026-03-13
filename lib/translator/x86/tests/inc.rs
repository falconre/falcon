use super::*;

/// INC rax: normal case.
/// 0x1234 + 1 = 0x1235
/// Expected flags: OF=0, ZF=0, SF=0.
/// CF must NOT be affected by INC per the AMD64 manual.
/// We set CF=0 before and assert it stays 0.
// Known Falcon bug: Falcon DOES modify CF for INC. Per the AMD64 manual,
// INC should NOT affect CF. These tests assert the correct manual behavior.
#[test]
fn inc_normal() {
    // inc rax; nop
    let bytes: Vec<u8> = vec![0x48, 0xff, 0xc0, 0x90];

    let driver = init_amd64_driver(
        bytes,
        vec![
            ("rax", il::const_(0x1234, 64)),
            ("CF", il::const_(0, 1)),
        ],
        Memory::new(Endian::Little),
    );

    let driver = step_to(driver, 0x3);

    assert_scalar(&driver, "rax", 0x1235);
    assert_flag(&driver, "OF", 0);
    assert_flag(&driver, "ZF", 0);
    assert_flag(&driver, "SF", 0);
    // CF must be preserved (not affected by INC per AMD manual).
    assert_flag(&driver, "CF", 0);
}

/// INC rax: zero result case (wraps from 0xFFFFFFFFFFFFFFFF to 0).
/// 0xFFFFFFFFFFFFFFFF + 1 = 0x0000000000000000 (mod 2^64)
/// Expected flags: OF=0 (signed: -1 + 1 = 0, no signed overflow), ZF=1, SF=0.
/// CF must NOT be affected. We set CF=1 before and assert it stays 1 to verify
/// that INC preserves CF rather than clearing it.
// Known Falcon bug: Falcon modifies CF for INC.
#[test]
fn inc_zero_result() {
    // inc rax; nop
    let bytes: Vec<u8> = vec![0x48, 0xff, 0xc0, 0x90];

    let driver = init_amd64_driver(
        bytes,
        vec![
            ("rax", il::const_(0xFFFFFFFFFFFFFFFF, 64)),
            ("CF", il::const_(1, 1)),
        ],
        Memory::new(Endian::Little),
    );

    let driver = step_to(driver, 0x3);

    assert_scalar(&driver, "rax", 0x0);
    assert_flag(&driver, "OF", 0);
    assert_flag(&driver, "ZF", 1);
    assert_flag(&driver, "SF", 0);
    // CF must be preserved at its prior value of 1 (INC does not affect CF).
    assert_flag(&driver, "CF", 1);
}

/// INC rax: signed overflow case.
/// 0x7FFFFFFFFFFFFFFF + 1 = 0x8000000000000000
/// Positive to negative => OF=1. MSB set => SF=1. Non-zero => ZF=0.
/// CF must NOT be affected. We set CF=0 before and assert it stays 0.
// Known Falcon bug: Falcon modifies CF for INC.
#[test]
fn inc_signed_overflow() {
    // inc rax; nop
    let bytes: Vec<u8> = vec![0x48, 0xff, 0xc0, 0x90];

    let driver = init_amd64_driver(
        bytes,
        vec![
            ("rax", il::const_(0x7FFFFFFFFFFFFFFF, 64)),
            ("CF", il::const_(0, 1)),
        ],
        Memory::new(Endian::Little),
    );

    let driver = step_to(driver, 0x3);

    assert_scalar(&driver, "rax", 0x8000000000000000);
    assert_flag(&driver, "OF", 1);
    assert_flag(&driver, "ZF", 0);
    assert_flag(&driver, "SF", 1);
    // CF must be preserved (not affected by INC per AMD manual).
    assert_flag(&driver, "CF", 0);
}
