use super::*;

#[test]
fn pslldq_shift_4_bytes() {
    // pslldq xmm0, 4 → 66 0f 73 f8 04
    // nop → 90
    let bytes: Vec<u8> = vec![0x66, 0x0f, 0x73, 0xf8, 0x04, 0x90];

    // xmm0 as 128-bit: 0x11111111_22222222_33333333_44444444
    // upper = 0x1111111122222222, lower = 0x3333333344444444
    let driver = init_amd64_driver(
        bytes,
        vec![
            ("xmm0", mk128const(0x1111111122222222, 0x3333333344444444)),
        ],
        Memory::new(Endian::Little),
    );

    let driver = step_to(driver, 0x5);

    // PSLLDQ: shift entire 128-bit register left by 4 bytes (32 bits),
    // zero-fill on the right.
    // 0x11111111_22222222_33333333_44444444 << 32 =
    // 0x22222222_33333333_44444444_00000000
    // upper = 0x2222222233333333, lower = 0x4444444400000000
    assert_xmm(&driver, "xmm0", 0x2222222233333333, 0x4444444400000000);
}

#[test]
fn pslldq_shift_8_bytes() {
    // pslldq xmm0, 8 → 66 0f 73 f8 08
    // nop → 90
    let bytes: Vec<u8> = vec![0x66, 0x0f, 0x73, 0xf8, 0x08, 0x90];

    // xmm0 = (upper=0xAABBCCDDEEFF0011, lower=0x2233445566778899)
    let driver = init_amd64_driver(
        bytes,
        vec![
            ("xmm0", mk128const(0xAABBCCDDEEFF0011, 0x2233445566778899)),
        ],
        Memory::new(Endian::Little),
    );

    let driver = step_to(driver, 0x5);

    // Shift left by 8 bytes = 64 bits
    // The lower 64 bits move to upper, lower becomes all zeros
    // upper = old lower = 0x2233445566778899
    // lower = 0x0000000000000000
    assert_xmm(&driver, "xmm0", 0x2233445566778899, 0x0000000000000000);
}
