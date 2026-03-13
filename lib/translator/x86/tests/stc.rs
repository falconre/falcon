use super::*;

/// STC: Set carry flag (CF = 1).
/// Encoding: 0xF9 (single byte).
/// AMD64 manual: STC sets the CF flag in the EFLAGS register.
/// Start with CF=0, execute STC, verify CF=1.
#[test]
fn stc_sets_carry_flag() {
    // stc; nop
    let bytes: Vec<u8> = vec![0xf9, 0x90];

    let driver = init_amd64_driver(
        bytes,
        vec![("CF", il::const_(0, 1))],
        Memory::new(Endian::Little),
    );

    let driver = step_to(driver, 0x1);

    assert_flag(&driver, "CF", 1);
}

/// STC when CF is already 1 should keep CF=1.
#[test]
fn stc_already_set() {
    // stc; nop
    let bytes: Vec<u8> = vec![0xf9, 0x90];

    let driver = init_amd64_driver(
        bytes,
        vec![("CF", il::const_(1, 1))],
        Memory::new(Endian::Little),
    );

    let driver = step_to(driver, 0x1);

    assert_flag(&driver, "CF", 1);
}
