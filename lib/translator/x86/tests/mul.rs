use super::*;

/// MUL rbx (64-bit unsigned multiply): RDX:RAX = RAX * RBX (unsigned).
/// Small multiply: RAX=5, RBX=3 → result=15, fits in RAX alone.
/// Expected: RDX=0, RAX=15, CF=0, OF=0 (upper half is zero).
#[test]
fn mul_r64_small() {
    // mul rbx; nop → 48 f7 e3 90
    let bytes: Vec<u8> = vec![0x48, 0xf7, 0xe3, 0x90];

    let driver = init_amd64_driver(
        bytes,
        vec![("rax", il::const_(5, 64)), ("rbx", il::const_(3, 64))],
        Memory::new(Endian::Little),
    );

    let driver = step_to(driver, 0x3);

    assert_scalar(&driver, "rax", 15);
    assert_scalar(&driver, "rdx", 0);
    assert_flag(&driver, "CF", 0);
    assert_flag(&driver, "OF", 0);
}

/// MUL rbx (64-bit unsigned multiply): large multiply producing overflow into RDX.
/// RAX=0xFFFFFFFFFFFFFFFF, RBX=2 → 128-bit product = 0x1_FFFFFFFFFFFFFFFE.
/// Expected: RDX=1, RAX=0xFFFFFFFFFFFFFFFE, CF=1, OF=1 (upper half non-zero).
#[test]
fn mul_r64_overflow() {
    // mul rbx; nop → 48 f7 e3 90
    let bytes: Vec<u8> = vec![0x48, 0xf7, 0xe3, 0x90];

    let driver = init_amd64_driver(
        bytes,
        vec![
            ("rax", il::const_(0xFFFFFFFFFFFFFFFF, 64)),
            ("rbx", il::const_(2, 64)),
        ],
        Memory::new(Endian::Little),
    );

    let driver = step_to(driver, 0x3);

    assert_scalar(&driver, "rax", 0xFFFFFFFFFFFFFFFE);
    assert_scalar(&driver, "rdx", 1);
    assert_flag(&driver, "CF", 1);
    assert_flag(&driver, "OF", 1);
}
