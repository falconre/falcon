use super::*;

/// CDQE: Sign-extend EAX into RAX (positive EAX, bit 31 = 0).
/// Per AMD64 manual: RAX <- sign-extend(EAX). No flags affected.
/// EAX = 0x7FFFFFFF (positive), so RAX = 0x000000007FFFFFFF.
#[test]
fn cdqe_positive_eax() {
    // cdqe  =>  48 98  (REX.W + opcode 98)
    // nop   =>  90
    let bytes: Vec<u8> = vec![0x48, 0x98, 0x90];

    // Set rax with EAX = 0x7FFFFFFF, upper 32 bits set to detect sign extension
    let driver = init_amd64_driver(
        bytes,
        vec![("rax", il::const_(0xFFFFFFFF7FFFFFFF, 64))],
        Memory::new(Endian::Little),
    );

    let driver = step_to(driver, 0x2);

    // RAX = sign_extend_32_to_64(0x7FFFFFFF) = 0x000000007FFFFFFF
    assert_scalar(&driver, "rax", 0x000000007FFFFFFF);
}

/// CDQE: Sign-extend EAX into RAX (negative EAX, bit 31 = 1).
/// Per AMD64 manual: RAX <- sign-extend(EAX). No flags affected.
/// EAX = 0x80000000 (negative), so RAX = 0xFFFFFFFF80000000.
#[test]
fn cdqe_negative_eax() {
    // cdqe  =>  48 98  (REX.W + opcode 98)
    // nop   =>  90
    let bytes: Vec<u8> = vec![0x48, 0x98, 0x90];

    // Set rax with EAX = 0x80000000, upper 32 bits zeroed
    let driver = init_amd64_driver(
        bytes,
        vec![("rax", il::const_(0x0000000080000000, 64))],
        Memory::new(Endian::Little),
    );

    let driver = step_to(driver, 0x2);

    // RAX = sign_extend_32_to_64(0x80000000) = 0xFFFFFFFF80000000
    assert_scalar(&driver, "rax", 0xFFFFFFFF80000000);
}
