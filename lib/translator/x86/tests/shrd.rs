use super::*;

/// SHRD rax, rbx, cl: double precision shift right by 8.
/// rax = 0x00000000000000FF, rbx = 0x00000000000000AB, rcx = 8
/// SHRD shifts dest right by count, filling vacated bits from LSBs of src.
/// Result = (rax >> 8) | (rbx << (64-8))
///        = 0x0000000000000000 | (0x00000000000000AB << 56)
///        = 0x0000000000000000 | 0xAB00000000000000
///        = 0xAB00000000000000
/// CF = last bit shifted out of dest = original dest bit (count-1) = bit 7
///   rax = 0x00000000000000FF: bits 7-0 = 0xFF. bit 7 = 1. CF = 1.
/// SF = 1 (MSB of result = 1), ZF = 0
#[test]
fn shrd_by_cl() {
    // shrd rax, rbx, cl; nop
    // Encoding: REX.W(48) 0F AD ModRM(D8); nop=90
    let bytes: Vec<u8> = vec![0x48, 0x0f, 0xad, 0xd8, 0x90];

    let driver = init_amd64_driver(
        bytes,
        vec![
            ("rax", il::const_(0x00000000000000FF, 64)),
            ("rbx", il::const_(0x00000000000000AB, 64)),
            ("rcx", il::const_(8, 64)),
        ],
        Memory::new(Endian::Little),
    );

    let driver = step_to(driver, 0x4);

    assert_scalar(&driver, "rax", 0xAB00000000000000);
    assert_flag(&driver, "CF", 1);
    assert_flag(&driver, "ZF", 0);
    assert_flag(&driver, "SF", 1);
}

/// SHRD rax, rbx, 4: double precision shift right with immediate count.
/// rax = 0xFEDCBA987654321F, rbx = 0x000000000000000F, count = 4
/// Result = (rax >> 4) | (rbx << 60)
///        = 0x0FEDCBA987654321 | (0xF << 60)
///        = 0x0FEDCBA987654321 | 0xF000000000000000
///        = 0xFFEDCBA987654321
/// CF = last bit shifted out = original dest bit (count-1) = bit 3
///   rax = 0x...321F: low nibble = 0xF = 1111. bit 3 = 1. CF = 1.
/// SF = 1 (MSB = 1), ZF = 0
#[test]
fn shrd_imm() {
    // shrd rax, rbx, 4; nop
    // Encoding: REX.W(48) 0F AC ModRM(D8) imm8(04); nop=90
    let bytes: Vec<u8> = vec![0x48, 0x0f, 0xac, 0xd8, 0x04, 0x90];

    let driver = init_amd64_driver(
        bytes,
        vec![
            ("rax", il::const_(0xFEDCBA987654321F, 64)),
            ("rbx", il::const_(0x000000000000000F, 64)),
        ],
        Memory::new(Endian::Little),
    );

    let driver = step_to(driver, 0x5);

    assert_scalar(&driver, "rax", 0xFFEDCBA987654321);
    assert_flag(&driver, "CF", 1);
    assert_flag(&driver, "ZF", 0);
    assert_flag(&driver, "SF", 1);
}
