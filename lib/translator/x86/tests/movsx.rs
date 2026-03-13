use super::*;

/// MOVSX eax, bx: sign-extend 16-bit to 32-bit, positive value (sign bit 0).
/// Per AMD64 manual: dest <- sign-extend(src), no flags affected.
/// In 64-bit mode, writing to eax implicitly zero-extends into rax.
/// bx = 0x7F00 (bit 15 = 0, positive), so eax = 0x00007F00, rax = 0x00007F00.
#[test]
fn movsx_eax_bx_positive() {
    // movsx eax, bx  =>  0f bf c3  (MOVSX r32,r/m16 + ModRM mod=11 reg=eax rm=ebx)
    // nop            =>  90
    let bytes: Vec<u8> = vec![0x0f, 0xbf, 0xc3, 0x90];

    let driver = init_amd64_driver(
        bytes,
        vec![
            ("rax", il::const_(0xFFFFFFFFFFFFFFFF, 64)),
            ("rbx", il::const_(0x7F00, 64)),
        ],
        Memory::new(Endian::Little),
    );

    let driver = step_to(driver, 0x3);

    // eax = sign_extend_16_to_32(0x7F00) = 0x00007F00
    // rax = zero_extend_32_to_64(0x00007F00) = 0x00007F00
    assert_scalar(&driver, "rax", 0x00007F00);
}

/// MOVSXD rax, ecx: sign-extend 32-bit to 64-bit, negative value (sign bit 1).
/// Per AMD64 manual: dest <- sign-extend(src), no flags affected.
/// ecx = 0x80000001 (bit 31 = 1, negative), so rax = 0xFFFFFFFF80000001.
#[test]
fn movsxd_rax_ecx_negative() {
    // movsxd rax, ecx  =>  48 63 c1  (REX.W + MOVSXD r64,r/m32 + ModRM mod=11 reg=rax rm=ecx)
    // nop              =>  90
    let bytes: Vec<u8> = vec![0x48, 0x63, 0xc1, 0x90];

    let driver = init_amd64_driver(
        bytes,
        vec![
            ("rax", il::const_(0, 64)),
            ("rcx", il::const_(0x80000001, 64)),
        ],
        Memory::new(Endian::Little),
    );

    let driver = step_to(driver, 0x3);

    // rax = sign_extend_32_to_64(0x80000001) = 0xFFFFFFFF80000001
    assert_scalar(&driver, "rax", 0xFFFFFFFF80000001);
}
