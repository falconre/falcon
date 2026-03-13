use super::*;

/// DIV rbx (64-bit unsigned divide): RDX:RAX / RBX.
/// RAX = quotient, RDX = remainder. Flags are undefined per the manual.
/// Simple case: RDX=0, RAX=100, RBX=7 → 100/7 = quotient 14, remainder 2.
#[test]
fn div_r64_simple() {
    // div rbx; nop → 48 f7 f3 90
    let bytes: Vec<u8> = vec![0x48, 0xf7, 0xf3, 0x90];

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

/// DIV rbx (64-bit unsigned divide): with upper bits in RDX.
/// RDX=1, RAX=0, RBX=2 → dividing 0x1_0000000000000000 (2^64) by 2.
/// Quotient = 0x8000000000000000, remainder = 0.
#[test]
fn div_r64_with_upper_bits() {
    // div rbx; nop → 48 f7 f3 90
    let bytes: Vec<u8> = vec![0x48, 0xf7, 0xf3, 0x90];

    let driver = init_amd64_driver(
        bytes,
        vec![
            ("rax", il::const_(0, 64)),
            ("rdx", il::const_(1, 64)),
            ("rbx", il::const_(2, 64)),
        ],
        Memory::new(Endian::Little),
    );

    let driver = step_to(driver, 0x3);

    assert_scalar(&driver, "rax", 0x8000000000000000);
    assert_scalar(&driver, "rdx", 0);
}
