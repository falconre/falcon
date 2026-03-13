use super::*;

/// CLD: Clear direction flag (DF = 0).
/// Encoding: 0xFC (single byte).
/// AMD64 manual: CLD clears the DF flag in the EFLAGS register.
/// Start with DF=1, execute CLD, verify DF=0.
#[test]
fn cld_clears_direction_flag() {
    // cld; nop
    let bytes: Vec<u8> = vec![0xfc, 0x90];

    let driver = init_amd64_driver(
        bytes,
        vec![("DF", il::const_(1, 1))],
        Memory::new(Endian::Little),
    );

    let driver = step_to(driver, 0x1);

    assert_flag(&driver, "DF", 0);
}

/// CLD when DF is already 0 should keep DF=0.
#[test]
fn cld_already_clear() {
    // cld; nop
    let bytes: Vec<u8> = vec![0xfc, 0x90];

    let driver = init_amd64_driver(
        bytes,
        vec![("DF", il::const_(0, 1))],
        Memory::new(Endian::Little),
    );

    let driver = step_to(driver, 0x1);

    assert_flag(&driver, "DF", 0);
}
