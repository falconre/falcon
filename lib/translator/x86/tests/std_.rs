use super::*;

/// STD: Set direction flag (DF = 1).
/// Encoding: 0xFD (single byte).
/// AMD64 manual: STD sets the DF flag in the EFLAGS register.
/// Start with DF=0, execute STD, verify DF=1.
#[test]
fn std_sets_direction_flag() {
    // std; nop
    let bytes: Vec<u8> = vec![0xfd, 0x90];

    let driver = init_amd64_driver(
        bytes,
        vec![("DF", il::const_(0, 1))],
        Memory::new(Endian::Little),
    );

    let driver = step_to(driver, 0x1);

    assert_flag(&driver, "DF", 1);
}

/// STD when DF is already 1 should keep DF=1.
#[test]
fn std_already_set() {
    // std; nop
    let bytes: Vec<u8> = vec![0xfd, 0x90];

    let driver = init_amd64_driver(
        bytes,
        vec![("DF", il::const_(1, 1))],
        Memory::new(Endian::Little),
    );

    let driver = step_to(driver, 0x1);

    assert_flag(&driver, "DF", 1);
}
