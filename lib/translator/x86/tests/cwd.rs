use super::*;

/// CWD: Sign-extend AX into DX:AX (positive AX, bit 15 = 0).
/// Per AMD64 manual: DX:AX <- sign-extend(AX). No flags affected.
/// AX = 0x7FFF (positive), so DX = 0x0000.
#[test]
fn cwd_positive_ax() {
    // cwd  =>  66 99  (operand-size prefix + opcode 99)
    // nop  =>  90
    let bytes: Vec<u8> = vec![0x66, 0x99, 0x90];

    // Set rax with AX = 0x7FFF, rdx with upper bits set to detect zeroing
    let driver = init_amd64_driver(
        bytes,
        vec![
            ("rax", il::const_(0xFF00FF00FF007FFF, 64)),
            ("rdx", il::const_(0xDEADBEEFDEADBEEF, 64)),
        ],
        Memory::new(Endian::Little),
    );

    let driver = step_to(driver, 0x2);

    // Per AMD64 manual: CWD sign-extends AX into DX:AX.
    // AX = 0x7FFF (bit 15 = 0), so DX = 0x0000.
    // AX should be unchanged at 0x7FFF.
    let rax = driver
        .state()
        .get_scalar("rax")
        .unwrap()
        .value_u64()
        .unwrap();
    let ax = rax & 0xFFFF;
    assert_eq!(ax, 0x7FFF, "AX expected 0x7FFF, got 0x{:04x}", ax);

    let rdx = driver
        .state()
        .get_scalar("rdx")
        .unwrap()
        .value_u64()
        .unwrap();
    let dx = rdx & 0xFFFF;
    assert_eq!(dx, 0x0000, "DX expected 0x0000, got 0x{:04x}", dx);
}

/// CWD: Sign-extend AX into DX:AX (negative AX, bit 15 = 1).
/// Per AMD64 manual: DX:AX <- sign-extend(AX). No flags affected.
/// AX = 0x8000 (negative), so DX = 0xFFFF.
#[test]
fn cwd_negative_ax() {
    // cwd  =>  66 99  (operand-size prefix + opcode 99)
    // nop  =>  90
    let bytes: Vec<u8> = vec![0x66, 0x99, 0x90];

    // Set rax with AX = 0x8000, rdx zeroed to detect sign extension
    let driver = init_amd64_driver(
        bytes,
        vec![
            ("rax", il::const_(0x0000000000008000, 64)),
            ("rdx", il::const_(0x0000000000000000, 64)),
        ],
        Memory::new(Endian::Little),
    );

    let driver = step_to(driver, 0x2);

    // Per AMD64 manual: CWD sign-extends AX into DX:AX.
    // AX = 0x8000 (bit 15 = 1), so DX = 0xFFFF.
    // AX should be unchanged at 0x8000.
    let rax = driver
        .state()
        .get_scalar("rax")
        .unwrap()
        .value_u64()
        .unwrap();
    let ax = rax & 0xFFFF;
    assert_eq!(ax, 0x8000, "AX expected 0x8000, got 0x{:04x}", ax);

    let rdx = driver
        .state()
        .get_scalar("rdx")
        .unwrap()
        .value_u64()
        .unwrap();
    let dx = rdx & 0xFFFF;
    assert_eq!(dx, 0xFFFF, "DX expected 0xFFFF, got 0x{:04x}", dx);
}
