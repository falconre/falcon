use super::*;

/// CDQ: Sign-extend EAX into EDX:EAX (positive EAX, bit 31 = 0).
/// Per AMD64 manual: EDX:EAX <- sign-extend(EAX). No flags affected.
/// In 64-bit mode, writing to EDX implicitly zero-extends into RDX (upper 32 bits zeroed).
/// EAX = 0x7FFFFFFF (positive), so EDX = 0x00000000, RDX = 0x0000000000000000.
#[test]
fn cdq_positive_eax() {
    // cdq  =>  99  (opcode 99 in default 32-bit operand size)
    // nop  =>  90
    let bytes: Vec<u8> = vec![0x99, 0x90];

    // Set rax with EAX = 0x7FFFFFFF, rdx with upper bits set to detect zeroing
    let driver = init_amd64_driver(
        bytes,
        vec![
            ("rax", il::const_(0x000000007FFFFFFF, 64)),
            ("rdx", il::const_(0xDEADBEEFDEADBEEF, 64)),
        ],
        Memory::new(Endian::Little),
    );

    let driver = step_to(driver, 0x1);

    // Per AMD64 manual: CDQ sign-extends EAX into EDX:EAX.
    // EAX = 0x7FFFFFFF (bit 31 = 0), so EDX = 0x00000000.
    // Writing EDX zero-extends into RDX, so RDX = 0x0000000000000000.
    // EAX should be unchanged.
    let rax = driver
        .state()
        .get_scalar("rax")
        .unwrap()
        .value_u64()
        .unwrap();
    let eax = rax & 0xFFFFFFFF;
    assert_eq!(
        eax, 0x7FFFFFFF,
        "EAX expected 0x7FFFFFFF, got 0x{:08x}",
        eax
    );

    assert_scalar(&driver, "rdx", 0x0000000000000000);
}

/// CDQ: Sign-extend EAX into EDX:EAX (negative EAX, bit 31 = 1).
/// Per AMD64 manual: EDX:EAX <- sign-extend(EAX). No flags affected.
/// In 64-bit mode, writing to EDX implicitly zero-extends into RDX (upper 32 bits zeroed).
/// EAX = 0x80000000 (negative), so EDX = 0xFFFFFFFF, RDX = 0x00000000FFFFFFFF.
#[test]
fn cdq_negative_eax() {
    // cdq  =>  99  (opcode 99 in default 32-bit operand size)
    // nop  =>  90
    let bytes: Vec<u8> = vec![0x99, 0x90];

    // Set rax with EAX = 0x80000000, rdx zeroed to detect sign extension
    let driver = init_amd64_driver(
        bytes,
        vec![
            ("rax", il::const_(0x0000000080000000, 64)),
            ("rdx", il::const_(0x0000000000000000, 64)),
        ],
        Memory::new(Endian::Little),
    );

    let driver = step_to(driver, 0x1);

    // Per AMD64 manual: CDQ sign-extends EAX into EDX:EAX.
    // EAX = 0x80000000 (bit 31 = 1), so EDX = 0xFFFFFFFF.
    // Writing EDX zero-extends into RDX, so RDX = 0x00000000FFFFFFFF.
    // EAX should be unchanged.
    let rax = driver
        .state()
        .get_scalar("rax")
        .unwrap()
        .value_u64()
        .unwrap();
    let eax = rax & 0xFFFFFFFF;
    assert_eq!(
        eax, 0x80000000,
        "EAX expected 0x80000000, got 0x{:08x}",
        eax
    );

    assert_scalar(&driver, "rdx", 0x00000000FFFFFFFF);
}
