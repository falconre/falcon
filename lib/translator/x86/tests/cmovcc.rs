use super::*;

// =============================================================================
// CMOVcc — Conditional Move
// AMD64 manual: If condition is true, dest = src; otherwise dest is unchanged.
// No flags are affected by CMOVcc.
// =============================================================================

// ---------------------------------------------------------------------------
// CMOVE rax, rbx  (condition: ZF=1)
// Encoding: 48 0f 44 c3
// ---------------------------------------------------------------------------

/// CMOVE rax, rbx with ZF=1: condition is met, rax should receive rbx value.
#[test]
fn cmove_condition_true() {
    // cmove rax, rbx; nop
    let bytes: Vec<u8> = vec![0x48, 0x0f, 0x44, 0xc3, 0x90];

    let driver = init_amd64_driver(
        bytes,
        vec![
            ("rax", il::const_(0x1111111111111111, 64)),
            ("rbx", il::const_(0x2222222222222222, 64)),
            ("ZF", il::const_(1, 1)),
        ],
        Memory::new(Endian::Little),
    );

    let driver = step_to(driver, 0x4);

    // ZF=1 means condition is true, so rax = rbx
    assert_scalar(&driver, "rax", 0x2222222222222222);
}

/// CMOVE rax, rbx with ZF=0: condition is not met, rax should be unchanged.
#[test]
fn cmove_condition_false() {
    // cmove rax, rbx; nop
    let bytes: Vec<u8> = vec![0x48, 0x0f, 0x44, 0xc3, 0x90];

    let driver = init_amd64_driver(
        bytes,
        vec![
            ("rax", il::const_(0x1111111111111111, 64)),
            ("rbx", il::const_(0x2222222222222222, 64)),
            ("ZF", il::const_(0, 1)),
        ],
        Memory::new(Endian::Little),
    );

    let driver = step_to(driver, 0x4);

    // ZF=0 means condition is false, rax stays unchanged
    assert_scalar(&driver, "rax", 0x1111111111111111);
}

// ---------------------------------------------------------------------------
// CMOVNE rax, rbx  (condition: ZF=0)
// Encoding: 48 0f 45 c3
// ---------------------------------------------------------------------------

/// CMOVNE rax, rbx with ZF=0: condition is met, rax should receive rbx value.
#[test]
fn cmovne_condition_true() {
    // cmovne rax, rbx; nop
    let bytes: Vec<u8> = vec![0x48, 0x0f, 0x45, 0xc3, 0x90];

    let driver = init_amd64_driver(
        bytes,
        vec![
            ("rax", il::const_(0xAAAAAAAAAAAAAAAA, 64)),
            ("rbx", il::const_(0xBBBBBBBBBBBBBBBB, 64)),
            ("ZF", il::const_(0, 1)),
        ],
        Memory::new(Endian::Little),
    );

    let driver = step_to(driver, 0x4);

    // ZF=0 means NE condition is true, so rax = rbx
    assert_scalar(&driver, "rax", 0xBBBBBBBBBBBBBBBB);
}

/// CMOVNE rax, rbx with ZF=1: condition is not met, rax should be unchanged.
#[test]
fn cmovne_condition_false() {
    // cmovne rax, rbx; nop
    let bytes: Vec<u8> = vec![0x48, 0x0f, 0x45, 0xc3, 0x90];

    let driver = init_amd64_driver(
        bytes,
        vec![
            ("rax", il::const_(0xAAAAAAAAAAAAAAAA, 64)),
            ("rbx", il::const_(0xBBBBBBBBBBBBBBBB, 64)),
            ("ZF", il::const_(1, 1)),
        ],
        Memory::new(Endian::Little),
    );

    let driver = step_to(driver, 0x4);

    // ZF=1 means NE condition is false, rax stays unchanged
    assert_scalar(&driver, "rax", 0xAAAAAAAAAAAAAAAA);
}

// ---------------------------------------------------------------------------
// CMOVB rax, rbx  (condition: CF=1)
// Encoding: 48 0f 42 c3
// ---------------------------------------------------------------------------

/// CMOVB rax, rbx with CF=1: condition is met, rax should receive rbx value.
#[test]
fn cmovb_condition_true() {
    // cmovb rax, rbx; nop
    let bytes: Vec<u8> = vec![0x48, 0x0f, 0x42, 0xc3, 0x90];

    let driver = init_amd64_driver(
        bytes,
        vec![
            ("rax", il::const_(0x0000000000000001, 64)),
            ("rbx", il::const_(0x00000000DEADBEEF, 64)),
            ("CF", il::const_(1, 1)),
        ],
        Memory::new(Endian::Little),
    );

    let driver = step_to(driver, 0x4);

    // CF=1 means B (below) condition is true, so rax = rbx
    assert_scalar(&driver, "rax", 0x00000000DEADBEEF);
}

/// CMOVB rax, rbx with CF=0: condition is not met, rax should be unchanged.
#[test]
fn cmovb_condition_false() {
    // cmovb rax, rbx; nop
    let bytes: Vec<u8> = vec![0x48, 0x0f, 0x42, 0xc3, 0x90];

    let driver = init_amd64_driver(
        bytes,
        vec![
            ("rax", il::const_(0x0000000000000001, 64)),
            ("rbx", il::const_(0x00000000DEADBEEF, 64)),
            ("CF", il::const_(0, 1)),
        ],
        Memory::new(Endian::Little),
    );

    let driver = step_to(driver, 0x4);

    // CF=0 means B condition is false, rax stays unchanged
    assert_scalar(&driver, "rax", 0x0000000000000001);
}

// ---------------------------------------------------------------------------
// CMOVG rax, rbx  (condition: ZF=0 AND SF=OF)
// Encoding: 48 0f 4f c3
// ---------------------------------------------------------------------------

/// CMOVG rax, rbx with ZF=0, SF=0, OF=0: condition is met (ZF=0 and SF==OF),
/// rax should receive rbx value.
#[test]
fn cmovg_condition_true() {
    // cmovg rax, rbx; nop
    let bytes: Vec<u8> = vec![0x48, 0x0f, 0x4f, 0xc3, 0x90];

    let driver = init_amd64_driver(
        bytes,
        vec![
            ("rax", il::const_(0x1000000000000000, 64)),
            ("rbx", il::const_(0x2000000000000000, 64)),
            ("ZF", il::const_(0, 1)),
            ("SF", il::const_(0, 1)),
            ("OF", il::const_(0, 1)),
        ],
        Memory::new(Endian::Little),
    );

    let driver = step_to(driver, 0x4);

    // ZF=0 and SF==OF => G condition is true, rax = rbx
    assert_scalar(&driver, "rax", 0x2000000000000000);
}

/// CMOVG rax, rbx with ZF=1, SF=0, OF=0: condition is not met (ZF=1 fails
/// the ZF=0 requirement), rax should be unchanged.
#[test]
fn cmovg_condition_false() {
    // cmovg rax, rbx; nop
    let bytes: Vec<u8> = vec![0x48, 0x0f, 0x4f, 0xc3, 0x90];

    let driver = init_amd64_driver(
        bytes,
        vec![
            ("rax", il::const_(0x1000000000000000, 64)),
            ("rbx", il::const_(0x2000000000000000, 64)),
            ("ZF", il::const_(1, 1)),
            ("SF", il::const_(0, 1)),
            ("OF", il::const_(0, 1)),
        ],
        Memory::new(Endian::Little),
    );

    let driver = step_to(driver, 0x4);

    // ZF=1 means G condition is false, rax stays unchanged
    assert_scalar(&driver, "rax", 0x1000000000000000);
}
