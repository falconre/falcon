use super::*;

#[test]
fn paddq_basic() {
    // paddq xmm0, xmm1 → 66 0f d4 c1
    // nop → 90
    let bytes: Vec<u8> = vec![0x66, 0x0f, 0xd4, 0xc1, 0x90];

    // xmm0 = (upper=0x0000000000000001, lower=0x0000000000000002)
    // xmm1 = (upper=0x0000000000000003, lower=0x0000000000000004)
    let driver = init_amd64_driver(
        bytes,
        vec![
            ("xmm0", mk128const(0x0000000000000001, 0x0000000000000002)),
            ("xmm1", mk128const(0x0000000000000003, 0x0000000000000004)),
        ],
        Memory::new(Endian::Little),
    );

    let driver = step_to(driver, 0x4);

    // PADDQ: xmm0[63:0] += xmm1[63:0], xmm0[127:64] += xmm1[127:64]
    // lower: 0x02 + 0x04 = 0x06
    // upper: 0x01 + 0x03 = 0x04
    assert_xmm(&driver, "xmm0", 0x0000000000000004, 0x0000000000000006);
}

#[test]
fn paddq_wrapping() {
    // paddq xmm0, xmm1 → 66 0f d4 c1
    // nop → 90
    let bytes: Vec<u8> = vec![0x66, 0x0f, 0xd4, 0xc1, 0x90];

    // Test wrapping addition (no overflow detection per AMD64 manual)
    // xmm0 = (upper=0xFFFFFFFFFFFFFFFF, lower=0x8000000000000001)
    // xmm1 = (upper=0x0000000000000002, lower=0x8000000000000001)
    let driver = init_amd64_driver(
        bytes,
        vec![
            ("xmm0", mk128const(0xFFFFFFFFFFFFFFFF, 0x8000000000000001)),
            ("xmm1", mk128const(0x0000000000000002, 0x8000000000000001)),
        ],
        Memory::new(Endian::Little),
    );

    let driver = step_to(driver, 0x4);

    // lower: 0x8000000000000001 + 0x8000000000000001 = 0x0000000000000002 (wraps)
    // upper: 0xFFFFFFFFFFFFFFFF + 0x0000000000000002 = 0x0000000000000001 (wraps)
    assert_xmm(&driver, "xmm0", 0x0000000000000001, 0x0000000000000002);
}
