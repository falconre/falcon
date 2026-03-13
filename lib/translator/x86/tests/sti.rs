use super::*;

/// STI: Set interrupt flag (IF = 1).
/// Encoding: 0xFB (single byte).
/// AMD64 manual: STI sets the IF flag in the EFLAGS register.
/// Start with IF=0, execute STI, verify IF=1.
#[test]
fn sti_sets_interrupt_flag() {
    // sti; nop
    let bytes: Vec<u8> = vec![0xfb, 0x90];

    let driver = init_amd64_driver(
        bytes,
        vec![("IF", il::const_(0, 1))],
        Memory::new(Endian::Little),
    );

    let driver = step_to(driver, 0x1);

    assert_flag(&driver, "IF", 1);
}

/// STI when IF is already 1 should keep IF=1.
#[test]
fn sti_already_set() {
    // sti; nop
    let bytes: Vec<u8> = vec![0xfb, 0x90];

    let driver = init_amd64_driver(
        bytes,
        vec![("IF", il::const_(1, 1))],
        Memory::new(Endian::Little),
    );

    let driver = step_to(driver, 0x1);

    assert_flag(&driver, "IF", 1);
}
