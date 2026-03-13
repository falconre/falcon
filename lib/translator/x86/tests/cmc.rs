use super::*;

/// CMC: Complement carry flag (CF = ~CF).
/// Encoding: 0xF5 (single byte).
/// AMD64 manual: CMC complements the CF flag in the EFLAGS register.
/// Start with CF=0, execute CMC, verify CF=1.
#[test]
fn cmc_complement_zero_to_one() {
    // cmc; nop
    let bytes: Vec<u8> = vec![0xf5, 0x90];

    let driver = init_amd64_driver(
        bytes,
        vec![("CF", il::const_(0, 1))],
        Memory::new(Endian::Little),
    );

    let driver = step_to(driver, 0x1);

    assert_flag(&driver, "CF", 1);
}

/// CMC: Start with CF=1, execute CMC, verify CF=0.
#[test]
fn cmc_complement_one_to_zero() {
    // cmc; nop
    let bytes: Vec<u8> = vec![0xf5, 0x90];

    let driver = init_amd64_driver(
        bytes,
        vec![("CF", il::const_(1, 1))],
        Memory::new(Endian::Little),
    );

    let driver = step_to(driver, 0x1);

    assert_flag(&driver, "CF", 0);
}
