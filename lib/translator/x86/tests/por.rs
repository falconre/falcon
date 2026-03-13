use super::*;

#[test]
fn por_basic() {
    // por xmm0, xmm1 → 66 0f eb c1
    // nop → 90
    let bytes: Vec<u8> = vec![0x66, 0x0f, 0xeb, 0xc1, 0x90];

    // xmm0 = (upper=0xFF00FF00FF00FF00, lower=0x00FF00FF00FF00FF)
    // xmm1 = (upper=0x00FF00FF00FF00FF, lower=0xFF00FF00FF00FF00)
    let driver = init_amd64_driver(
        bytes,
        vec![
            ("xmm0", mk128const(0xFF00FF00FF00FF00, 0x00FF00FF00FF00FF)),
            ("xmm1", mk128const(0x00FF00FF00FF00FF, 0xFF00FF00FF00FF00)),
        ],
        Memory::new(Endian::Little),
    );

    let driver = step_to(driver, 0x4);

    // POR: xmm0 = xmm0 | xmm1
    // upper: 0xFF00FF00FF00FF00 | 0x00FF00FF00FF00FF = 0xFFFFFFFFFFFFFFFF
    // lower: 0x00FF00FF00FF00FF | 0xFF00FF00FF00FF00 = 0xFFFFFFFFFFFFFFFF
    assert_xmm(&driver, "xmm0", 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF);
}

#[test]
fn por_partial() {
    // por xmm0, xmm1 → 66 0f eb c1
    // nop → 90
    let bytes: Vec<u8> = vec![0x66, 0x0f, 0xeb, 0xc1, 0x90];

    let driver = init_amd64_driver(
        bytes,
        vec![
            ("xmm0", mk128const(0x1234567890ABCDEF, 0x0000000000000000)),
            ("xmm1", mk128const(0x0000000000000000, 0xFEDCBA9876543210)),
        ],
        Memory::new(Endian::Little),
    );

    let driver = step_to(driver, 0x4);

    // upper: 0x1234567890ABCDEF | 0x0000000000000000 = 0x1234567890ABCDEF
    // lower: 0x0000000000000000 | 0xFEDCBA9876543210 = 0xFEDCBA9876543210
    assert_xmm(&driver, "xmm0", 0x1234567890ABCDEF, 0xFEDCBA9876543210);
}
