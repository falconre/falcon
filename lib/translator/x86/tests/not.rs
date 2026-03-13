use super::*;

// NOT rax => 0x48, 0xf7, 0xd0 (REX.W + NOT r/m64 + ModRM)
// Per AMD64 manual: dest = ~dest (bitwise complement); NO flags are affected.

#[test]
fn not_rax_normal() {
    // not rax
    // nop
    let bytes: Vec<u8> = vec![0x48, 0xf7, 0xd0, 0x90];

    let driver = init_amd64_driver(
        bytes,
        vec![("rax", il::const_(0xFF00FF00FF00FF00, 64))],
        Memory::new(Endian::Little),
    );

    let driver = step_to(driver, 0x3);

    // ~0xFF00FF00FF00FF00 = 0x00FF00FF00FF00FF
    assert_scalar(&driver, "rax", 0x00FF00FF00FF00FF);
}

#[test]
fn not_rax_all_ones_to_zero() {
    // not rax
    // nop
    let bytes: Vec<u8> = vec![0x48, 0xf7, 0xd0, 0x90];

    let driver = init_amd64_driver(
        bytes,
        vec![("rax", il::const_(0xFFFFFFFFFFFFFFFF, 64))],
        Memory::new(Endian::Little),
    );

    let driver = step_to(driver, 0x3);

    // ~0xFFFFFFFFFFFFFFFF = 0x0000000000000000
    assert_scalar(&driver, "rax", 0x0000000000000000);
}

#[test]
fn not_rax_zero_to_all_ones() {
    // not rax
    // nop
    let bytes: Vec<u8> = vec![0x48, 0xf7, 0xd0, 0x90];

    let driver = init_amd64_driver(
        bytes,
        vec![("rax", il::const_(0x0000000000000000, 64))],
        Memory::new(Endian::Little),
    );

    let driver = step_to(driver, 0x3);

    // ~0x0000000000000000 = 0xFFFFFFFFFFFFFFFF
    assert_scalar(&driver, "rax", 0xFFFFFFFFFFFFFFFF);
}
