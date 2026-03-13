use super::*;

#[test]
fn psubb_basic() {
    // psubb xmm0, xmm1 → 66 0f f8 c1
    // nop → 90
    let bytes: Vec<u8> = vec![0x66, 0x0f, 0xf8, 0xc1, 0x90];

    // xmm0 bytes (upper qword): 10 20 30 40 50 60 70 80
    // xmm0 bytes (lower qword): 01 02 03 04 05 06 07 08
    // xmm1 bytes (upper qword): 01 01 01 01 01 01 01 01
    // xmm1 bytes (lower qword): 00 01 02 03 04 05 06 07
    let driver = init_amd64_driver(
        bytes,
        vec![
            ("xmm0", mk128const(0x1020304050607080, 0x0102030405060708)),
            ("xmm1", mk128const(0x0101010101010101, 0x0001020304050607)),
        ],
        Memory::new(Endian::Little),
    );

    let driver = step_to(driver, 0x4);

    // PSUBB: each byte of xmm0 -= corresponding byte of xmm1
    // upper: 0F 1F 2F 3F 4F 5F 6F 7F
    // lower: 01 01 01 01 01 01 01 01
    assert_xmm(&driver, "xmm0", 0x0F1F2F3F4F5F6F7F, 0x0101010101010101);
}

#[test]
fn psubb_wrapping() {
    // psubb xmm0, xmm1 → 66 0f f8 c1
    // nop → 90
    let bytes: Vec<u8> = vec![0x66, 0x0f, 0xf8, 0xc1, 0x90];

    // Test wrapping: 0x00 - 0x01 = 0xFF for each byte
    // xmm0 = all zeros
    // xmm1 = all 0x01
    let driver = init_amd64_driver(
        bytes,
        vec![
            ("xmm0", mk128const(0x0000000000000000, 0x0000000000000000)),
            ("xmm1", mk128const(0x0101010101010101, 0x0101010101010101)),
        ],
        Memory::new(Endian::Little),
    );

    let driver = step_to(driver, 0x4);

    // Every byte: 0x00 - 0x01 = 0xFF (wrapping)
    assert_xmm(&driver, "xmm0", 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF);
}
