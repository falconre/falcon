use super::*;

/// DEC rax: normal case.
/// 0x1235 - 1 = 0x1234
/// Expected flags: OF=0, ZF=0, SF=0.
/// CF must NOT be affected by DEC per the AMD64 manual.
/// We set CF=0 before and assert it stays 0.
// Known Falcon bug: Falcon DOES modify CF for DEC. Per the AMD64 manual,
// DEC should NOT affect CF. These tests assert the correct manual behavior.
#[test]
fn dec_normal() {
    // dec rax; nop
    let bytes: Vec<u8> = vec![0x48, 0xff, 0xc8, 0x90];

    let driver = init_amd64_driver(
        bytes,
        vec![
            ("rax", il::const_(0x1235, 64)),
            ("CF", il::const_(0, 1)),
        ],
        Memory::new(Endian::Little),
    );

    let driver = step_to(driver, 0x3);

    assert_scalar(&driver, "rax", 0x1234);
    assert_flag(&driver, "OF", 0);
    assert_flag(&driver, "ZF", 0);
    assert_flag(&driver, "SF", 0);
    // CF must be preserved (not affected by DEC per AMD manual).
    assert_flag(&driver, "CF", 0);
}

/// DEC rax: zero result case.
/// 0x0000000000000001 - 1 = 0x0000000000000000
/// Expected flags: OF=0, ZF=1, SF=0.
/// CF must NOT be affected. We set CF=1 before and assert it stays 1.
// Known Falcon bug: Falcon modifies CF for DEC.
#[test]
fn dec_zero_result() {
    // dec rax; nop
    let bytes: Vec<u8> = vec![0x48, 0xff, 0xc8, 0x90];

    let driver = init_amd64_driver(
        bytes,
        vec![
            ("rax", il::const_(0x0000000000000001, 64)),
            ("CF", il::const_(1, 1)),
        ],
        Memory::new(Endian::Little),
    );

    let driver = step_to(driver, 0x3);

    assert_scalar(&driver, "rax", 0x0);
    assert_flag(&driver, "OF", 0);
    assert_flag(&driver, "ZF", 1);
    assert_flag(&driver, "SF", 0);
    // CF must be preserved at its prior value of 1 (DEC does not affect CF).
    assert_flag(&driver, "CF", 1);
}

/// DEC rax: signed overflow case.
/// 0x8000000000000000 - 1 = 0x7FFFFFFFFFFFFFFF
/// Most-negative to most-positive => signed overflow (OF=1).
/// MSB=0 => SF=0. Non-zero => ZF=0.
/// CF must NOT be affected. We set CF=0 before and assert it stays 0.
// Known Falcon bug: Falcon modifies CF for DEC.
#[test]
fn dec_signed_overflow() {
    // dec rax; nop
    let bytes: Vec<u8> = vec![0x48, 0xff, 0xc8, 0x90];

    let driver = init_amd64_driver(
        bytes,
        vec![
            ("rax", il::const_(0x8000000000000000, 64)),
            ("CF", il::const_(0, 1)),
        ],
        Memory::new(Endian::Little),
    );

    let driver = step_to(driver, 0x3);

    assert_scalar(&driver, "rax", 0x7FFFFFFFFFFFFFFF);
    assert_flag(&driver, "OF", 1);
    assert_flag(&driver, "ZF", 0);
    assert_flag(&driver, "SF", 0);
    // CF must be preserved (not affected by DEC per AMD manual).
    assert_flag(&driver, "CF", 0);
}
