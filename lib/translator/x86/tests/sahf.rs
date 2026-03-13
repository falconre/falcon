use super::*;

/// SAHF: Store AH into Flags.
/// Encoding: 0x9E (single byte).
/// AMD64 manual: Loads SF, ZF, AF, PF, CF from the AH register into EFLAGS.
///   SF = AH bit 7, ZF = AH bit 6, AF = AH bit 4, PF = AH bit 2, CF = AH bit 0.
/// AH is bits [15:8] of RAX (equivalently bits [15:8] of AX).
///
/// Test with AH = 0xD5 = 0b11010101:
///   SF = bit 7 = 1
///   ZF = bit 6 = 1
///   AF = bit 4 = 1  (Falcon does not set AF -- commented out in implementation)
///   PF = bit 2 = 1  (Falcon does not set PF -- commented out in implementation)
///   CF = bit 0 = 1
///
/// Set rax = 0xD500 so that AH = 0xD5, AL = 0x00.
///
/// Known bug: Falcon's SAHF has reversed operand order in shr expressions
/// (shifts the constant by AX instead of AX by the constant) and reads from
/// the wrong bits of AX (reads AX bits 0/6/7 instead of AH bits 0/6/7 which
/// are AX bits 8/14/15). These tests assert correct AMD64 manual behavior.
#[test]
fn sahf_all_flags_set() {
    // sahf; nop
    let bytes: Vec<u8> = vec![0x9e, 0x90];

    // AH = 0xD5 = 0b11010101 => SF=1, ZF=1, CF=1
    // rax = 0xD500 (AH in bits [15:8])
    let driver = init_amd64_driver(
        bytes,
        vec![
            ("rax", il::const_(0xD500, 64)),
            ("CF", il::const_(0, 1)),
            ("ZF", il::const_(0, 1)),
            ("SF", il::const_(0, 1)),
        ],
        Memory::new(Endian::Little),
    );

    let driver = step_to(driver, 0x1);

    assert_flag(&driver, "CF", 1);
    assert_flag(&driver, "ZF", 1);
    assert_flag(&driver, "SF", 1);
}

/// SAHF with AH = 0x00 = 0b00000000: all flags should be cleared.
///   SF = 0, ZF = 0, CF = 0
/// Set rax = 0x0000 so AH = 0x00.
#[test]
fn sahf_all_flags_clear() {
    // sahf; nop
    let bytes: Vec<u8> = vec![0x9e, 0x90];

    // AH = 0x00 => SF=0, ZF=0, CF=0
    let driver = init_amd64_driver(
        bytes,
        vec![
            ("rax", il::const_(0x0000, 64)),
            ("CF", il::const_(1, 1)),
            ("ZF", il::const_(1, 1)),
            ("SF", il::const_(1, 1)),
        ],
        Memory::new(Endian::Little),
    );

    let driver = step_to(driver, 0x1);

    assert_flag(&driver, "CF", 0);
    assert_flag(&driver, "ZF", 0);
    assert_flag(&driver, "SF", 0);
}

/// SAHF with AH = 0x01 = 0b00000001: only CF should be set.
///   SF = 0 (bit 7), ZF = 0 (bit 6), CF = 1 (bit 0)
/// Set rax = 0x0100 so AH = 0x01.
#[test]
fn sahf_only_cf_set() {
    // sahf; nop
    let bytes: Vec<u8> = vec![0x9e, 0x90];

    let driver = init_amd64_driver(
        bytes,
        vec![
            ("rax", il::const_(0x0100, 64)),
            ("CF", il::const_(0, 1)),
            ("ZF", il::const_(1, 1)),
            ("SF", il::const_(1, 1)),
        ],
        Memory::new(Endian::Little),
    );

    let driver = step_to(driver, 0x1);

    assert_flag(&driver, "CF", 1);
    assert_flag(&driver, "ZF", 0);
    assert_flag(&driver, "SF", 0);
}

/// SAHF with AH = 0xC0 = 0b11000000: SF and ZF set, CF clear.
///   SF = 1 (bit 7), ZF = 1 (bit 6), CF = 0 (bit 0)
/// Set rax = 0xC000 so AH = 0xC0.
#[test]
fn sahf_sf_zf_set_cf_clear() {
    // sahf; nop
    let bytes: Vec<u8> = vec![0x9e, 0x90];

    let driver = init_amd64_driver(
        bytes,
        vec![
            ("rax", il::const_(0xC000, 64)),
            ("CF", il::const_(1, 1)),
            ("ZF", il::const_(0, 1)),
            ("SF", il::const_(0, 1)),
        ],
        Memory::new(Endian::Little),
    );

    let driver = step_to(driver, 0x1);

    assert_flag(&driver, "CF", 0);
    assert_flag(&driver, "ZF", 1);
    assert_flag(&driver, "SF", 1);
}
