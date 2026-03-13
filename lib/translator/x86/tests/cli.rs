use super::*;

/// CLI: Clear interrupt flag (IF = 0).
/// Encoding: 0xFA (single byte).
/// AMD64 manual: CLI clears the IF flag in the EFLAGS register.
/// Start with IF=1, execute CLI, verify IF=0.
#[test]
fn cli_clears_interrupt_flag() {
    // cli; nop
    let bytes: Vec<u8> = vec![0xfa, 0x90];

    let driver = init_amd64_driver(
        bytes,
        vec![("IF", il::const_(1, 1))],
        Memory::new(Endian::Little),
    );

    let driver = step_to(driver, 0x1);

    assert_flag(&driver, "IF", 0);
}

/// CLI when IF is already 0 should keep IF=0.
#[test]
fn cli_already_clear() {
    // cli; nop
    let bytes: Vec<u8> = vec![0xfa, 0x90];

    let driver = init_amd64_driver(
        bytes,
        vec![("IF", il::const_(0, 1))],
        Memory::new(Endian::Little),
    );

    let driver = step_to(driver, 0x1);

    assert_flag(&driver, "IF", 0);
}
