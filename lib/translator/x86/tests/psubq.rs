use super::*;

#[test]
fn psubq_basic() {
    // psubq xmm0, xmm1 → 66 0f fb c1
    // nop → 90
    let bytes: Vec<u8> = vec![0x66, 0x0f, 0xfb, 0xc1, 0x90];

    // xmm0 = (upper=0x0000000000000005, lower=0x000000000000000A)
    // xmm1 = (upper=0x0000000000000003, lower=0x0000000000000004)
    let driver = init_amd64_driver(
        bytes,
        vec![
            ("xmm0", mk128const(0x0000000000000005, 0x000000000000000A)),
            ("xmm1", mk128const(0x0000000000000003, 0x0000000000000004)),
        ],
        Memory::new(Endian::Little),
    );

    let driver = step_to(driver, 0x4);

    // PSUBQ: xmm0[63:0] -= xmm1[63:0], xmm0[127:64] -= xmm1[127:64]
    // lower: 0x0A - 0x04 = 0x06
    // upper: 0x05 - 0x03 = 0x02
    assert_xmm(&driver, "xmm0", 0x0000000000000002, 0x0000000000000006);
}

#[test]
fn psubq_wrapping() {
    // psubq xmm0, xmm1 → 66 0f fb c1
    // nop → 90
    let bytes: Vec<u8> = vec![0x66, 0x0f, 0xfb, 0xc1, 0x90];

    // Test wrapping subtraction
    // xmm0 = (upper=0x0000000000000000, lower=0x0000000000000001)
    // xmm1 = (upper=0x0000000000000001, lower=0x0000000000000002)
    let driver = init_amd64_driver(
        bytes,
        vec![
            ("xmm0", mk128const(0x0000000000000000, 0x0000000000000001)),
            ("xmm1", mk128const(0x0000000000000001, 0x0000000000000002)),
        ],
        Memory::new(Endian::Little),
    );

    let driver = step_to(driver, 0x4);

    // lower: 0x01 - 0x02 = 0xFFFFFFFFFFFFFFFF (wraps)
    // upper: 0x00 - 0x01 = 0xFFFFFFFFFFFFFFFF (wraps)
    assert_xmm(&driver, "xmm0", 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF);
}
