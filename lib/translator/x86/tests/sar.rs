use super::*;

/// SAR rax, 1: arithmetic shift right by 1, check OF flag.
/// rax = 0x8000000000000003 (negative, bit 63=1, bits 1-0=11)
/// Result = 0xC000000000000001 (shift right 1, MSB filled with sign bit=1)
/// CF = last bit shifted out = original bit 0 = 1
/// OF (count==1) = 0 (always 0 for SAR with count 1, per AMD64 manual)
/// SF = 1 (MSB of result = 1), ZF = 0
#[test]
fn sar_by_one() {
    // sar rax, 1; nop
    // Encoding: REX.W(48) D1 /7 => D1 F8; nop=90
    let bytes: Vec<u8> = vec![0x48, 0xd1, 0xf8, 0x90];

    let driver = init_amd64_driver(
        bytes,
        vec![("rax", il::const_(0x8000000000000003, 64))],
        Memory::new(Endian::Little),
    );

    let driver = step_to(driver, 0x3);

    assert_scalar(&driver, "rax", 0xC000000000000001);
    assert_flag(&driver, "CF", 1);
    assert_flag(&driver, "OF", 0);
    assert_flag(&driver, "SF", 1);
    assert_flag(&driver, "ZF", 0);
}

/// SAR rax, cl: arithmetic shift right by 8, negative value.
/// rax = 0xFEDCBA9876543210, rcx = 8
/// Sign bit = 1. Shift right 8, filling MSBs with 1s.
/// Result = 0xFFFEDCBA98765432
/// CF = last bit shifted out = original bit (count-1) = bit 7
///   Low byte of rax = 0x10 = 0001_0000, bit 7 = 0
/// SF = 1, ZF = 0
#[test]
fn sar_by_cl_negative() {
    // sar rax, cl; nop
    // Encoding: REX.W(48) D3 /7 => D3 F8; nop=90
    let bytes: Vec<u8> = vec![0x48, 0xd3, 0xf8, 0x90];

    let driver = init_amd64_driver(
        bytes,
        vec![
            ("rax", il::const_(0xFEDCBA9876543210, 64)),
            ("rcx", il::const_(8, 64)),
        ],
        Memory::new(Endian::Little),
    );

    let driver = step_to(driver, 0x3);

    assert_scalar(&driver, "rax", 0xFFFEDCBA98765432);
    assert_flag(&driver, "CF", 0);
    assert_flag(&driver, "SF", 1);
    assert_flag(&driver, "ZF", 0);
}

/// SAR rax, cl: arithmetic shift right to produce zero from positive value.
/// rax = 0x0000000000000001, rcx = 1
/// Result = 0x0000000000000000 (positive value, sign bit=0 fills MSBs)
/// CF = bit 0 = 1
/// ZF = 1, SF = 0
#[test]
fn sar_to_zero() {
    // sar rax, cl; nop
    let bytes: Vec<u8> = vec![0x48, 0xd3, 0xf8, 0x90];

    let driver = init_amd64_driver(
        bytes,
        vec![
            ("rax", il::const_(0x0000000000000001, 64)),
            ("rcx", il::const_(1, 64)),
        ],
        Memory::new(Endian::Little),
    );

    let driver = step_to(driver, 0x3);

    assert_scalar(&driver, "rax", 0x0000000000000000);
    assert_flag(&driver, "CF", 1);
    assert_flag(&driver, "ZF", 1);
    assert_flag(&driver, "SF", 0);
}
