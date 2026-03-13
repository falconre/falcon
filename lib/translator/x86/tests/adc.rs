use super::*;

/// ADC rax, rbx: normal case with CF=0 input.
/// 0x1234 + 0x5678 + 0 = 0x68AC
/// Expected flags: CF=0, OF=0, ZF=0, SF=0
#[test]
fn adc_normal_cf_clear() {
    // adc rax, rbx; nop
    let bytes: Vec<u8> = vec![0x48, 0x11, 0xd8, 0x90];

    let driver = init_amd64_driver(
        bytes,
        vec![
            ("rax", il::const_(0x1234, 64)),
            ("rbx", il::const_(0x5678, 64)),
            ("CF", il::const_(0, 1)),
        ],
        Memory::new(Endian::Little),
    );

    let driver = step_to(driver, 0x3);

    assert_scalar(&driver, "rax", 0x68AC);
    assert_flag(&driver, "CF", 0);
    assert_flag(&driver, "OF", 0);
    assert_flag(&driver, "ZF", 0);
    assert_flag(&driver, "SF", 0);
}

/// ADC rax, rbx: zero result with CF=1 input.
/// 0x0000000000000000 + 0xFFFFFFFFFFFFFFFF + 1 = 0 (mod 2^64)
/// Expected: result is 0, CF=1 (carry out), OF=0, ZF=1, SF=0
#[test]
fn adc_zero_result_with_carry_in() {
    // adc rax, rbx; nop
    let bytes: Vec<u8> = vec![0x48, 0x11, 0xd8, 0x90];

    let driver = init_amd64_driver(
        bytes,
        vec![
            ("rax", il::const_(0x0000000000000000, 64)),
            ("rbx", il::const_(0xFFFFFFFFFFFFFFFF, 64)),
            ("CF", il::const_(1, 1)),
        ],
        Memory::new(Endian::Little),
    );

    let driver = step_to(driver, 0x3);

    assert_scalar(&driver, "rax", 0x0);
    assert_flag(&driver, "CF", 1);
    assert_flag(&driver, "OF", 0);
    assert_flag(&driver, "ZF", 1);
    assert_flag(&driver, "SF", 0);
}

/// ADC rax, rbx: signed overflow triggered by carry-in.
/// 0x7FFFFFFFFFFFFFFE + 0x0000000000000001 + CF=1 = 0x8000000000000000
/// Two positives plus carry produce negative => OF=1.
/// No unsigned carry => CF=0. MSB set => SF=1. Non-zero => ZF=0.
#[test]
fn adc_signed_overflow_via_carry() {
    // adc rax, rbx; nop
    let bytes: Vec<u8> = vec![0x48, 0x11, 0xd8, 0x90];

    let driver = init_amd64_driver(
        bytes,
        vec![
            ("rax", il::const_(0x7FFFFFFFFFFFFFFE, 64)),
            ("rbx", il::const_(0x0000000000000001, 64)),
            ("CF", il::const_(1, 1)),
        ],
        Memory::new(Endian::Little),
    );

    let driver = step_to(driver, 0x3);

    assert_scalar(&driver, "rax", 0x8000000000000000);
    assert_flag(&driver, "CF", 0);
    assert_flag(&driver, "OF", 1);
    assert_flag(&driver, "ZF", 0);
    assert_flag(&driver, "SF", 1);
}

/// ADC rax, rbx: negative signed overflow with CF=0.
/// 0x8000000000000000 + 0x8000000000000000 + 0 = 0 (mod 2^64)
/// Two negative numbers produce a non-negative result => OF=1.
/// Unsigned carry => CF=1. Result is zero => ZF=1, SF=0.
#[test]
fn adc_negative_overflow() {
    // adc rax, rbx; nop
    let bytes: Vec<u8> = vec![0x48, 0x11, 0xd8, 0x90];

    let driver = init_amd64_driver(
        bytes,
        vec![
            ("rax", il::const_(0x8000000000000000, 64)),
            ("rbx", il::const_(0x8000000000000000, 64)),
            ("CF", il::const_(0, 1)),
        ],
        Memory::new(Endian::Little),
    );

    let driver = step_to(driver, 0x3);

    assert_scalar(&driver, "rax", 0x0);
    assert_flag(&driver, "CF", 1);
    assert_flag(&driver, "OF", 1);
    assert_flag(&driver, "ZF", 1);
    assert_flag(&driver, "SF", 0);
}
