use super::*;

/// SHL rax, 1: shift left by 1, check OF flag.
/// rax = 0xC000000000000001
/// Result = 0x8000000000000002 (shift left 1, MSB 1 shifted out)
/// CF = last bit shifted out = original bit 63 = 1
/// OF (count==1) = MSB(result) XOR CF = 1 XOR 1 = 0
/// SF = 1 (MSB of result), ZF = 0
#[test]
fn shl_by_one() {
    // shl rax, 1; nop
    // Encoding: REX.W(48) D1 /4 => D1 E0; nop=90
    let bytes: Vec<u8> = vec![0x48, 0xd1, 0xe0, 0x90];

    let driver = init_amd64_driver(
        bytes,
        vec![("rax", il::const_(0xC000000000000001, 64))],
        Memory::new(Endian::Little),
    );

    let driver = step_to(driver, 0x3);

    assert_scalar(&driver, "rax", 0x8000000000000002);
    assert_flag(&driver, "CF", 1);
    assert_flag(&driver, "OF", 0);
    assert_flag(&driver, "SF", 1);
    assert_flag(&driver, "ZF", 0);
}

/// SHL rax, cl: shift left by 4.
/// rax = 0x0123456789ABCDEF, rcx = 4
/// Result = 0x123456789ABCDEF0
/// CF = last bit shifted out = original bit (64-4) = bit 60 = 0
///   (0x0123... => nibble at bit 63-60 = 0x0 = 0000, bit 60 = 0)
/// SF = 0 (MSB of result: 0x1 = 0001, bit 63 = 0), ZF = 0
#[test]
fn shl_by_cl() {
    // shl rax, cl; nop
    // Encoding: REX.W(48) D3 /4 => D3 E0; nop=90
    let bytes: Vec<u8> = vec![0x48, 0xd3, 0xe0, 0x90];

    let driver = init_amd64_driver(
        bytes,
        vec![
            ("rax", il::const_(0x0123456789ABCDEF, 64)),
            ("rcx", il::const_(4, 64)),
        ],
        Memory::new(Endian::Little),
    );

    let driver = step_to(driver, 0x3);

    assert_scalar(&driver, "rax", 0x123456789ABCDEF0);
    assert_flag(&driver, "CF", 0);
    assert_flag(&driver, "ZF", 0);
    assert_flag(&driver, "SF", 0);
}

/// SHL rax, cl: shift to zero.
/// rax = 0x8000000000000000, rcx = 1
/// Result = 0x0000000000000000 (single 1-bit at MSB shifted out)
/// CF = bit 63 of original = 1
/// OF (count==1) = MSB(result) XOR CF = 0 XOR 1 = 1
/// ZF = 1, SF = 0
#[test]
fn shl_to_zero() {
    // shl rax, cl; nop
    let bytes: Vec<u8> = vec![0x48, 0xd3, 0xe0, 0x90];

    let driver = init_amd64_driver(
        bytes,
        vec![
            ("rax", il::const_(0x8000000000000000, 64)),
            ("rcx", il::const_(1, 64)),
        ],
        Memory::new(Endian::Little),
    );

    let driver = step_to(driver, 0x3);

    assert_scalar(&driver, "rax", 0x0000000000000000);
    assert_flag(&driver, "CF", 1);
    assert_flag(&driver, "OF", 1);
    assert_flag(&driver, "ZF", 1);
    assert_flag(&driver, "SF", 0);
}
