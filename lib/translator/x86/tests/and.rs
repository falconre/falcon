use super::*;

// AND rax, rbx => 0x48, 0x21, 0xd8 (REX.W + AND r/m64, r64 + ModRM)
// Per AMD64 manual: dest = dest & src; CF=0, OF=0, ZF=(result==0), SF=MSB(result)

#[test]
fn and_rax_rbx_normal() {
    // and rax, rbx
    // nop
    let bytes: Vec<u8> = vec![0x48, 0x21, 0xd8, 0x90];

    let driver = init_amd64_driver(
        bytes,
        vec![
            ("rax", il::const_(0xFF00FF00FF00FF00, 64)),
            ("rbx", il::const_(0x0F0F0F0F0F0F0F0F, 64)),
        ],
        Memory::new(Endian::Little),
    );

    let driver = step_to(driver, 0x3);

    // 0xFF00FF00FF00FF00 & 0x0F0F0F0F0F0F0F0F = 0x0F000F000F000F00
    assert_scalar(&driver, "rax", 0x0F000F000F000F00);
    // rbx unchanged
    assert_scalar(&driver, "rbx", 0x0F0F0F0F0F0F0F0F);
    // CF and OF always cleared by AND
    assert_flag(&driver, "CF", 0);
    assert_flag(&driver, "OF", 0);
    // Result is non-zero => ZF=0
    assert_flag(&driver, "ZF", 0);
    // MSB of 0x0F000F000F000F00 is 0 => SF=0
    assert_flag(&driver, "SF", 0);
}

#[test]
fn and_rax_rbx_zero_result() {
    // and rax, rbx
    // nop
    let bytes: Vec<u8> = vec![0x48, 0x21, 0xd8, 0x90];

    let driver = init_amd64_driver(
        bytes,
        vec![
            ("rax", il::const_(0xFF00FF00FF00FF00, 64)),
            ("rbx", il::const_(0x00FF00FF00FF00FF, 64)),
        ],
        Memory::new(Endian::Little),
    );

    let driver = step_to(driver, 0x3);

    // 0xFF00FF00FF00FF00 & 0x00FF00FF00FF00FF = 0x0000000000000000
    assert_scalar(&driver, "rax", 0x0000000000000000);
    assert_flag(&driver, "CF", 0);
    assert_flag(&driver, "OF", 0);
    // Result is zero => ZF=1
    assert_flag(&driver, "ZF", 1);
    // MSB of 0 is 0 => SF=0
    assert_flag(&driver, "SF", 0);
}

#[test]
fn and_rax_rbx_sign_flag() {
    // and rax, rbx
    // nop
    let bytes: Vec<u8> = vec![0x48, 0x21, 0xd8, 0x90];

    let driver = init_amd64_driver(
        bytes,
        vec![
            ("rax", il::const_(0xFFFFFFFFFFFFFFFF, 64)),
            ("rbx", il::const_(0x8000000000000000, 64)),
        ],
        Memory::new(Endian::Little),
    );

    let driver = step_to(driver, 0x3);

    // 0xFFFFFFFFFFFFFFFF & 0x8000000000000000 = 0x8000000000000000
    assert_scalar(&driver, "rax", 0x8000000000000000);
    assert_flag(&driver, "CF", 0);
    assert_flag(&driver, "OF", 0);
    // Result is non-zero => ZF=0
    assert_flag(&driver, "ZF", 0);
    // MSB of 0x8000000000000000 is 1 => SF=1
    assert_flag(&driver, "SF", 1);
}
