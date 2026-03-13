use super::*;

/// IDIV rbx (64-bit signed divide): RDX:RAX / RBX (signed).
/// RAX = quotient, RDX = remainder. Sign of remainder = sign of dividend.
/// Flags are undefined per the manual.
/// Positive case: RDX=0, RAX=100, RBX=7 → 100/7 = quotient 14, remainder 2.
#[test]
fn idiv_r64_positive() {
    // idiv rbx; nop → 48 f7 fb 90
    let bytes: Vec<u8> = vec![0x48, 0xf7, 0xfb, 0x90];

    let driver = init_amd64_driver(
        bytes,
        vec![
            ("rax", il::const_(100, 64)),
            ("rdx", il::const_(0, 64)),
            ("rbx", il::const_(7, 64)),
        ],
        Memory::new(Endian::Little),
    );

    let driver = step_to(driver, 0x3);

    assert_scalar(&driver, "rax", 14);
    assert_scalar(&driver, "rdx", 2);
}

/// IDIV rbx (64-bit signed divide): negative dividend.
/// RDX:RAX = -100 (sign-extended 128-bit): RDX=0xFFFFFFFFFFFFFFFF, RAX=0xFFFFFFFFFFFFFF9C.
/// RBX = 7. Signed division: -100 / 7 = quotient -14, remainder -2.
/// -14 = 0xFFFFFFFFFFFFFFF2, -2 = 0xFFFFFFFFFFFFFFFE.
#[test]
fn idiv_r64_negative_dividend() {
    // idiv rbx; nop → 48 f7 fb 90
    let bytes: Vec<u8> = vec![0x48, 0xf7, 0xfb, 0x90];

    let driver = init_amd64_driver(
        bytes,
        vec![
            ("rax", il::const_(0xFFFFFFFFFFFFFF9C, 64)), // -100
            ("rdx", il::const_(0xFFFFFFFFFFFFFFFF, 64)), // sign extension
            ("rbx", il::const_(7, 64)),
        ],
        Memory::new(Endian::Little),
    );

    let driver = step_to(driver, 0x3);

    assert_scalar(&driver, "rax", 0xFFFFFFFFFFFFFFF2); // -14
    assert_scalar(&driver, "rdx", 0xFFFFFFFFFFFFFFFE); // -2
}
