use super::*;

/// CWDE: Sign-extend AX into EAX (positive AX, bit 15 = 0).
/// Per AMD64 manual: EAX <- sign-extend(AX). No flags affected.
/// In 64-bit mode, writing to EAX implicitly zero-extends into RAX (upper 32 bits zeroed).
/// AX = 0x7FFF (positive), so EAX = 0x00007FFF, RAX = 0x00007FFF.
#[test]
fn cwde_positive_ax() {
    // cwde  =>  98  (opcode 98 in default 32-bit operand size)
    // nop   =>  90
    let bytes: Vec<u8> = vec![0x98, 0x90];

    // Set rax with AX = 0x7FFF, upper bits set to detect zero-extension
    let driver = init_amd64_driver(
        bytes,
        vec![("rax", il::const_(0xFFFFFFFF00007FFF, 64))],
        Memory::new(Endian::Little),
    );

    let driver = step_to(driver, 0x1);

    // EAX = sign_extend_16_to_32(0x7FFF) = 0x00007FFF
    // RAX = zero_extend_32_to_64(0x00007FFF) = 0x00007FFF
    assert_scalar(&driver, "rax", 0x00007FFF);
}

/// CWDE: Sign-extend AX into EAX (negative AX, bit 15 = 1).
/// Per AMD64 manual: EAX <- sign-extend(AX). No flags affected.
/// In 64-bit mode, writing to EAX implicitly zero-extends into RAX.
/// AX = 0x8000 (negative), so EAX = 0xFFFF8000, RAX = 0x00000000FFFF8000.
#[test]
fn cwde_negative_ax() {
    // cwde  =>  98  (opcode 98 in default 32-bit operand size)
    // nop   =>  90
    let bytes: Vec<u8> = vec![0x98, 0x90];

    // Set rax with AX = 0x8000, upper bits zeroed
    let driver = init_amd64_driver(
        bytes,
        vec![("rax", il::const_(0x0000000000008000, 64))],
        Memory::new(Endian::Little),
    );

    let driver = step_to(driver, 0x1);

    // EAX = sign_extend_16_to_32(0x8000) = 0xFFFF8000
    // RAX = zero_extend_32_to_64(0xFFFF8000) = 0x00000000FFFF8000
    assert_scalar(&driver, "rax", 0x00000000FFFF8000);
}
