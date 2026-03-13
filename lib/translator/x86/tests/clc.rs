use super::*;

/// CLC: Clear carry flag (CF = 0).
/// Encoding: 0xF8 (single byte).
/// AMD64 manual: CLC clears the CF flag in the EFLAGS register.
/// Start with CF=1, execute CLC, verify CF=0.
#[test]
fn clc_clears_carry_flag() {
    // clc; nop
    let bytes: Vec<u8> = vec![0xf8, 0x90];

    let driver = init_amd64_driver(
        bytes,
        vec![("CF", il::const_(1, 1))],
        Memory::new(Endian::Little),
    );

    let driver = step_to(driver, 0x1);

    assert_flag(&driver, "CF", 0);
}

/// CLC when CF is already 0 should keep CF=0.
#[test]
fn clc_already_clear() {
    // clc; nop
    let bytes: Vec<u8> = vec![0xf8, 0x90];

    let driver = init_amd64_driver(
        bytes,
        vec![("CF", il::const_(0, 1))],
        Memory::new(Endian::Little),
    );

    let driver = step_to(driver, 0x1);

    assert_flag(&driver, "CF", 0);
}
