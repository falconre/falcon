use super::*;

// OR rax, rbx => 0x48, 0x09, 0xd8 (REX.W + OR r/m64, r64 + ModRM)
// Per AMD64 manual: dest = dest | src; CF=0, OF=0, ZF=(result==0), SF=MSB(result)

#[test]
fn or_rax_rbx_normal() {
    // or rax, rbx
    // nop
    let bytes: Vec<u8> = vec![0x48, 0x09, 0xd8, 0x90];

    let driver = init_amd64_driver(
        bytes,
        vec![
            ("rax", il::const_(0xFF00FF0000000000, 64)),
            ("rbx", il::const_(0x00FF00FF00000000, 64)),
        ],
        Memory::new(Endian::Little),
    );

    let driver = step_to(driver, 0x3);

    // 0xFF00FF0000000000 | 0x00FF00FF00000000 = 0xFFFFFFFF00000000
    assert_scalar(&driver, "rax", 0xFFFFFFFF00000000);
    // rbx unchanged
    assert_scalar(&driver, "rbx", 0x00FF00FF00000000);
    // CF and OF always cleared by OR
    assert_flag(&driver, "CF", 0);
    assert_flag(&driver, "OF", 0);
    // Result is non-zero => ZF=0
    assert_flag(&driver, "ZF", 0);
    // MSB of 0xFFFFFFFF00000000 is 1 => SF=1
    assert_flag(&driver, "SF", 1);
}

#[test]
fn or_rax_rbx_zero_result() {
    // or rax, rbx
    // nop
    let bytes: Vec<u8> = vec![0x48, 0x09, 0xd8, 0x90];

    let driver = init_amd64_driver(
        bytes,
        vec![
            ("rax", il::const_(0x0000000000000000, 64)),
            ("rbx", il::const_(0x0000000000000000, 64)),
        ],
        Memory::new(Endian::Little),
    );

    let driver = step_to(driver, 0x3);

    // 0 | 0 = 0
    assert_scalar(&driver, "rax", 0x0000000000000000);
    assert_flag(&driver, "CF", 0);
    assert_flag(&driver, "OF", 0);
    // Result is zero => ZF=1
    assert_flag(&driver, "ZF", 1);
    // MSB of 0 is 0 => SF=0
    assert_flag(&driver, "SF", 0);
}

#[test]
fn or_rax_rbx_sign_flag() {
    // or rax, rbx
    // nop
    let bytes: Vec<u8> = vec![0x48, 0x09, 0xd8, 0x90];

    let driver = init_amd64_driver(
        bytes,
        vec![
            ("rax", il::const_(0x8000000000000000, 64)),
            ("rbx", il::const_(0x0000000000000001, 64)),
        ],
        Memory::new(Endian::Little),
    );

    let driver = step_to(driver, 0x3);

    // 0x8000000000000000 | 0x0000000000000001 = 0x8000000000000001
    assert_scalar(&driver, "rax", 0x8000000000000001);
    assert_flag(&driver, "CF", 0);
    assert_flag(&driver, "OF", 0);
    // Result is non-zero => ZF=0
    assert_flag(&driver, "ZF", 0);
    // MSB of 0x8000000000000001 is 1 => SF=1
    assert_flag(&driver, "SF", 1);
}
