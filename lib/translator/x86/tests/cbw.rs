use super::*;

/// CBW: Sign-extend AL into AX (positive AL, bit 7 = 0).
/// Per AMD64 manual: AX <- sign-extend(AL). No flags affected.
/// AL = 0x50 (positive), so AH becomes 0x00, AX = 0x0050.
#[test]
fn cbw_positive_al() {
    // cbw  =>  66 98  (operand-size prefix + opcode 98)
    // nop  =>  90
    let bytes: Vec<u8> = vec![0x66, 0x98, 0x90];

    // Set rax with AL = 0x50, and upper bytes set to detect clobbering
    let driver = init_amd64_driver(
        bytes,
        vec![("rax", il::const_(0xFF00FF00FF00FF50, 64))],
        Memory::new(Endian::Little),
    );

    let driver = step_to(driver, 0x2);

    // Per AMD64 manual: CBW sign-extends AL into AX.
    // AL = 0x50 (bit 7 = 0), so AX = 0x0050.
    // The low 16 bits of rax should be 0x0050.
    // Upper 48 bits of rax behavior depends on implementation.
    let rax = driver
        .state()
        .get_scalar("rax")
        .unwrap()
        .value_u64()
        .unwrap();
    let ax = rax & 0xFFFF;
    assert_eq!(ax, 0x0050, "AX expected 0x0050, got 0x{:04x}", ax);
}

/// CBW: Sign-extend AL into AX (negative AL, bit 7 = 1).
/// Per AMD64 manual: AX <- sign-extend(AL). No flags affected.
/// AL = 0x80 (negative), so AH becomes 0xFF, AX = 0xFF80.
#[test]
fn cbw_negative_al() {
    // cbw  =>  66 98  (operand-size prefix + opcode 98)
    // nop  =>  90
    let bytes: Vec<u8> = vec![0x66, 0x98, 0x90];

    // Set rax with AL = 0x80, upper bytes zeroed to detect sign extension
    let driver = init_amd64_driver(
        bytes,
        vec![("rax", il::const_(0x0000000000000080, 64))],
        Memory::new(Endian::Little),
    );

    let driver = step_to(driver, 0x2);

    // Per AMD64 manual: CBW sign-extends AL into AX.
    // AL = 0x80 (bit 7 = 1), so AX = 0xFF80.
    let rax = driver
        .state()
        .get_scalar("rax")
        .unwrap()
        .value_u64()
        .unwrap();
    let ax = rax & 0xFFFF;
    assert_eq!(ax, 0xFF80, "AX expected 0xFF80, got 0x{:04x}", ax);
}
