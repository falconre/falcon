use super::*;

#[test]
fn pxor_basic() {
    // pxor xmm0, xmm1 → 66 0f ef c1
    // nop → 90
    let bytes: Vec<u8> = vec![0x66, 0x0f, 0xef, 0xc1, 0x90];

    let driver = init_amd64_driver(
        bytes,
        vec![
            ("xmm0", mk128const(0x00000000000000FF, 0x00000000000000AA)),
            ("xmm1", mk128const(0x000000000000000F, 0x0000000000000055)),
        ],
        Memory::new(Endian::Little),
    );

    let driver = step_to(driver, 0x4);

    // PXOR: xmm0 = xmm0 ^ xmm1
    // upper: 0xFF ^ 0x0F = 0xF0
    // lower: 0xAA ^ 0x55 = 0xFF
    assert_xmm(&driver, "xmm0", 0x00000000000000F0, 0x00000000000000FF);
}

#[test]
fn pxor_self_zeroing() {
    // pxor xmm0, xmm0 → 66 0f ef c0
    // nop → 90
    let bytes: Vec<u8> = vec![0x66, 0x0f, 0xef, 0xc0, 0x90];

    // XOR with self should produce zero (common idiom to zero a register)
    let driver = init_amd64_driver(
        bytes,
        vec![
            ("xmm0", mk128const(0xDEADBEEFCAFEBABE, 0x1234567890ABCDEF)),
        ],
        Memory::new(Endian::Little),
    );

    let driver = step_to(driver, 0x4);

    assert_xmm(&driver, "xmm0", 0x0000000000000000, 0x0000000000000000);
}
