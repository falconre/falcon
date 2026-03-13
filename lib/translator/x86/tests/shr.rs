use super::*;

/// SHR rax, 1: logical shift right by 1, check OF flag.
/// rax = 0x8000000000000001
/// Result = 0x4000000000000000 (shift right 1, bit 0 shifted out, MSB filled with 0)
/// CF = last bit shifted out = original bit 0 = 1
/// OF (count==1) = MSB of original operand = 1
/// SF = 0 (MSB of result = 0), ZF = 0
#[test]
fn shr_by_one() {
    // shr rax, 1; nop
    // Encoding: REX.W(48) D1 /5 => D1 E8; nop=90
    let bytes: Vec<u8> = vec![0x48, 0xd1, 0xe8, 0x90];

    let driver = init_amd64_driver(
        bytes,
        vec![("rax", il::const_(0x8000000000000001, 64))],
        Memory::new(Endian::Little),
    );

    let driver = step_to(driver, 0x3);

    assert_scalar(&driver, "rax", 0x4000000000000000);
    assert_flag(&driver, "CF", 1);
    assert_flag(&driver, "OF", 1);
    assert_flag(&driver, "SF", 0);
    assert_flag(&driver, "ZF", 0);
}

/// SHR rax, cl: logical shift right by 4.
/// rax = 0x0123456789ABCDEF, rcx = 4
/// Result = 0x00123456789ABCDE
/// CF = last bit shifted out = original bit (count-1) = bit 3 = 1
///   (0x...DEF => 0xF = 1111, bit 3 = 1)
/// SF = 0, ZF = 0
#[test]
fn shr_by_cl() {
    // shr rax, cl; nop
    // Encoding: REX.W(48) D3 /5 => D3 E8; nop=90
    let bytes: Vec<u8> = vec![0x48, 0xd3, 0xe8, 0x90];

    let driver = init_amd64_driver(
        bytes,
        vec![
            ("rax", il::const_(0x0123456789ABCDEF, 64)),
            ("rcx", il::const_(4, 64)),
        ],
        Memory::new(Endian::Little),
    );

    let driver = step_to(driver, 0x3);

    assert_scalar(&driver, "rax", 0x00123456789ABCDE);
    assert_flag(&driver, "CF", 1);
    assert_flag(&driver, "ZF", 0);
    assert_flag(&driver, "SF", 0);
}

/// SHR rax, cl: shift to zero.
/// rax = 0x0000000000000001, rcx = 1
/// Result = 0x0000000000000000
/// CF = bit 0 of original = 1
/// OF (count==1) = MSB of original = 0
/// ZF = 1, SF = 0
#[test]
fn shr_to_zero() {
    // shr rax, cl; nop
    let bytes: Vec<u8> = vec![0x48, 0xd3, 0xe8, 0x90];

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
    assert_flag(&driver, "OF", 0);
    assert_flag(&driver, "ZF", 1);
    assert_flag(&driver, "SF", 0);
}
