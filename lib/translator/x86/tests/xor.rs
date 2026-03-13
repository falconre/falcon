use super::*;

// XOR rax, rbx => 0x48, 0x31, 0xd8 (REX.W + XOR r/m64, r64 + ModRM)
// Per AMD64 manual: dest = dest ^ src; CF=0, OF=0, ZF=(result==0), SF=MSB(result)

#[test]
fn xor_rax_rbx_normal() {
    // xor rax, rbx
    // nop
    let bytes: Vec<u8> = vec![0x48, 0x31, 0xd8, 0x90];

    let driver = init_amd64_driver(
        bytes,
        vec![
            ("rax", il::const_(0x0F0F0F0F0F0F0F0F, 64)),
            ("rbx", il::const_(0x00FF00FF00FF00FF, 64)),
        ],
        Memory::new(Endian::Little),
    );

    let driver = step_to(driver, 0x3);

    // 0x0F0F0F0F0F0F0F0F ^ 0x00FF00FF00FF00FF = 0x0FF00FF00FF00FF0
    assert_scalar(&driver, "rax", 0x0FF00FF00FF00FF0);
    // rbx unchanged
    assert_scalar(&driver, "rbx", 0x00FF00FF00FF00FF);
    // CF and OF always cleared by XOR
    assert_flag(&driver, "CF", 0);
    assert_flag(&driver, "OF", 0);
    // Result is non-zero => ZF=0
    assert_flag(&driver, "ZF", 0);
    // MSB of 0x0FF00FF00FF00FF0 is 0 => SF=0
    assert_flag(&driver, "SF", 0);
}

#[test]
fn xor_rax_rbx_zero_result() {
    // xor rax, rbx (with rax == rbx, producing zero)
    // nop
    let bytes: Vec<u8> = vec![0x48, 0x31, 0xd8, 0x90];

    let driver = init_amd64_driver(
        bytes,
        vec![
            ("rax", il::const_(0x123456789ABCDEF0, 64)),
            ("rbx", il::const_(0x123456789ABCDEF0, 64)),
        ],
        Memory::new(Endian::Little),
    );

    let driver = step_to(driver, 0x3);

    // 0x123456789ABCDEF0 ^ 0x123456789ABCDEF0 = 0
    assert_scalar(&driver, "rax", 0x0000000000000000);
    assert_flag(&driver, "CF", 0);
    assert_flag(&driver, "OF", 0);
    // Result is zero => ZF=1
    assert_flag(&driver, "ZF", 1);
    // MSB of 0 is 0 => SF=0
    assert_flag(&driver, "SF", 0);
}

#[test]
fn xor_rax_rbx_sign_flag() {
    // xor rax, rbx
    // nop
    let bytes: Vec<u8> = vec![0x48, 0x31, 0xd8, 0x90];

    let driver = init_amd64_driver(
        bytes,
        vec![
            ("rax", il::const_(0xFF00FF00FF00FF00, 64)),
            ("rbx", il::const_(0x0F0F0F0F0F0F0F0F, 64)),
        ],
        Memory::new(Endian::Little),
    );

    let driver = step_to(driver, 0x3);

    // 0xFF00FF00FF00FF00 ^ 0x0F0F0F0F0F0F0F0F = 0xF00FF00FF00FF00F
    assert_scalar(&driver, "rax", 0xF00FF00FF00FF00F);
    assert_flag(&driver, "CF", 0);
    assert_flag(&driver, "OF", 0);
    // Result is non-zero => ZF=0
    assert_flag(&driver, "ZF", 0);
    // MSB of 0xF00FF00FF00FF00F is 1 => SF=1
    assert_flag(&driver, "SF", 1);
}
