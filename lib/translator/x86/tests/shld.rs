use super::*;

/// SHLD rax, rbx, cl: double precision shift left by 8.
/// rax = 0xFF00000000000000, rbx = 0xAB00000000000000, rcx = 8
/// SHLD shifts dest left by count, filling vacated bits from MSBs of src.
/// Result = (rax << 8) | (rbx >> (64-8))
///        = 0x0000000000000000 | (0xAB00000000000000 >> 56)
///        = 0x0000000000000000 | 0x00000000000000AB
///        = 0x00000000000000AB
/// CF = last bit shifted out of dest = original dest bit (64-count) = bit 56
///   rax = 0xFF00000000000000: bits 63-56 = 0xFF = all 1s. bit 56 = 1. CF = 1.
/// SF = 0, ZF = 0
#[test]
fn shld_by_cl() {
    // shld rax, rbx, cl; nop
    // Encoding: REX.W(48) 0F A5 ModRM(D8); nop=90
    let bytes: Vec<u8> = vec![0x48, 0x0f, 0xa5, 0xd8, 0x90];

    let driver = init_amd64_driver(
        bytes,
        vec![
            ("rax", il::const_(0xFF00000000000000, 64)),
            ("rbx", il::const_(0xAB00000000000000, 64)),
            ("rcx", il::const_(8, 64)),
        ],
        Memory::new(Endian::Little),
    );

    let driver = step_to(driver, 0x4);

    assert_scalar(&driver, "rax", 0x00000000000000AB);
    assert_flag(&driver, "CF", 1);
    assert_flag(&driver, "ZF", 0);
    assert_flag(&driver, "SF", 0);
}

/// SHLD rax, rbx, 4: double precision shift left with immediate count.
/// rax = 0x123456789ABCDEF0, rbx = 0xFEDCBA9876543210, count = 4
/// Result = (rax << 4) | (rbx >> 60)
///        = 0x23456789ABCDEF00 | 0x000000000000000F
///        = 0x23456789ABCDEF0F
/// CF = last bit shifted out = original dest bit (64-4) = bit 60
///   rax = 0x123456789ABCDEF0: nibble at bits 63-60 = 0x1 = 0001. bit 60 = 1.
/// SF = 0, ZF = 0
#[test]
fn shld_imm() {
    // shld rax, rbx, 4; nop
    // Encoding: REX.W(48) 0F A4 ModRM(D8) imm8(04); nop=90
    let bytes: Vec<u8> = vec![0x48, 0x0f, 0xa4, 0xd8, 0x04, 0x90];

    let driver = init_amd64_driver(
        bytes,
        vec![
            ("rax", il::const_(0x123456789ABCDEF0, 64)),
            ("rbx", il::const_(0xFEDCBA9876543210, 64)),
        ],
        Memory::new(Endian::Little),
    );

    let driver = step_to(driver, 0x5);

    assert_scalar(&driver, "rax", 0x23456789ABCDEF0F);
    assert_flag(&driver, "CF", 1);
    assert_flag(&driver, "ZF", 0);
    assert_flag(&driver, "SF", 0);
}
