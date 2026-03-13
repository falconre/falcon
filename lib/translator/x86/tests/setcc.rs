use super::*;

// =============================================================================
// SETcc — Set Byte on Condition
// AMD64 manual: Sets the destination byte to 1 if condition is true, 0 if false.
// No flags are affected.
// =============================================================================

// ---------------------------------------------------------------------------
// SETE al  (condition: ZF=1)
// Encoding: 0f 94 c0
// ---------------------------------------------------------------------------

/// SETE al with ZF=1: condition is met, al should be set to 1.
/// Upper bits of rax are preserved (only the low byte is written).
#[test]
fn sete_condition_true() {
    // sete al; nop
    let bytes: Vec<u8> = vec![0x0f, 0x94, 0xc0, 0x90];

    let driver = init_amd64_driver(
        bytes,
        vec![
            ("rax", il::const_(0xFF00FF00FF00FF00, 64)),
            ("ZF", il::const_(1, 1)),
        ],
        Memory::new(Endian::Little),
    );

    let driver = step_to(driver, 0x3);

    // ZF=1 means E condition is true, al = 1.
    // Upper 56 bits of rax preserved: 0xFF00FF00FF00FF00 with low byte replaced by 0x01.
    assert_scalar(&driver, "rax", 0xFF00FF00FF00FF01);
}

/// SETE al with ZF=0: condition is not met, al should be set to 0.
#[test]
fn sete_condition_false() {
    // sete al; nop
    let bytes: Vec<u8> = vec![0x0f, 0x94, 0xc0, 0x90];

    let driver = init_amd64_driver(
        bytes,
        vec![
            ("rax", il::const_(0xFF00FF00FF00FFFF, 64)),
            ("ZF", il::const_(0, 1)),
        ],
        Memory::new(Endian::Little),
    );

    let driver = step_to(driver, 0x3);

    // ZF=0 means E condition is false, al = 0.
    // Upper 56 bits preserved: 0xFF00FF00FF00FF00 with low byte = 0x00.
    assert_scalar(&driver, "rax", 0xFF00FF00FF00FF00);
}

// ---------------------------------------------------------------------------
// SETNE al  (condition: ZF=0)
// Encoding: 0f 95 c0
// ---------------------------------------------------------------------------

/// SETNE al with ZF=0: condition is met, al should be set to 1.
#[test]
fn setne_condition_true() {
    // setne al; nop
    let bytes: Vec<u8> = vec![0x0f, 0x95, 0xc0, 0x90];

    let driver = init_amd64_driver(
        bytes,
        vec![
            ("rax", il::const_(0x0000000000000000, 64)),
            ("ZF", il::const_(0, 1)),
        ],
        Memory::new(Endian::Little),
    );

    let driver = step_to(driver, 0x3);

    // ZF=0 means NE condition is true, al = 1.
    assert_scalar(&driver, "rax", 0x0000000000000001);
}

/// SETNE al with ZF=1: condition is not met, al should be set to 0.
#[test]
fn setne_condition_false() {
    // setne al; nop
    let bytes: Vec<u8> = vec![0x0f, 0x95, 0xc0, 0x90];

    let driver = init_amd64_driver(
        bytes,
        vec![
            ("rax", il::const_(0x00000000000000FF, 64)),
            ("ZF", il::const_(1, 1)),
        ],
        Memory::new(Endian::Little),
    );

    let driver = step_to(driver, 0x3);

    // ZF=1 means NE condition is false, al = 0.
    // Upper bits preserved, low byte cleared.
    assert_scalar(&driver, "rax", 0x0000000000000000);
}

// ---------------------------------------------------------------------------
// SETL al  (condition: SF != OF)
// Encoding: 0f 9c c0
// ---------------------------------------------------------------------------

/// SETL al with SF=1, OF=0: condition is met (SF != OF), al = 1.
#[test]
fn setl_condition_true() {
    // setl al; nop
    let bytes: Vec<u8> = vec![0x0f, 0x9c, 0xc0, 0x90];

    let driver = init_amd64_driver(
        bytes,
        vec![
            ("rax", il::const_(0x0000000000000000, 64)),
            ("SF", il::const_(1, 1)),
            ("OF", il::const_(0, 1)),
        ],
        Memory::new(Endian::Little),
    );

    let driver = step_to(driver, 0x3);

    // SF=1, OF=0 => SF != OF => L condition is true, al = 1.
    assert_scalar(&driver, "rax", 0x0000000000000001);
}

/// SETL al with SF=0, OF=0: condition is not met (SF == OF), al = 0.
#[test]
fn setl_condition_false() {
    // setl al; nop
    let bytes: Vec<u8> = vec![0x0f, 0x9c, 0xc0, 0x90];

    let driver = init_amd64_driver(
        bytes,
        vec![
            ("rax", il::const_(0x00000000000000FF, 64)),
            ("SF", il::const_(0, 1)),
            ("OF", il::const_(0, 1)),
        ],
        Memory::new(Endian::Little),
    );

    let driver = step_to(driver, 0x3);

    // SF=0, OF=0 => SF == OF => L condition is false, al = 0.
    assert_scalar(&driver, "rax", 0x0000000000000000);
}
