use super::*;

#[test]
fn pminub_alternating() {
    // pminub xmm0, xmm1 → 66 0f da c1
    // nop → 90
    let bytes: Vec<u8> = vec![0x66, 0x0f, 0xda, 0xc1, 0x90];

    // Upper bytes: FF 00 FF 00 FF 00 FF 00 vs 00 FF 00 FF 00 FF 00 FF
    // Lower bytes: 01 02 03 04 05 06 07 08 vs 08 07 06 05 04 03 02 01
    let driver = init_amd64_driver(
        bytes,
        vec![
            ("xmm0", mk128const(0xFF00FF00FF00FF00, 0x0102030405060708)),
            ("xmm1", mk128const(0x00FF00FF00FF00FF, 0x0807060504030201)),
        ],
        Memory::new(Endian::Little),
    );

    let driver = step_to(driver, 0x4);

    // PMINUB: each byte = min(xmm0_byte, xmm1_byte) unsigned
    // upper: min(FF,00)=00, min(00,FF)=00, ... all zeros
    // lower: min(01,08)=01, min(02,07)=02, min(03,06)=03, min(04,05)=04,
    //        min(05,04)=04, min(06,03)=03, min(07,02)=02, min(08,01)=01
    assert_xmm(&driver, "xmm0", 0x0000000000000000, 0x0102030404030201);
}

#[test]
fn pminub_equal() {
    // pminub xmm0, xmm1 → 66 0f da c1
    // nop → 90
    let bytes: Vec<u8> = vec![0x66, 0x0f, 0xda, 0xc1, 0x90];

    // When both are equal, result should be the same value
    let driver = init_amd64_driver(
        bytes,
        vec![
            ("xmm0", mk128const(0xAABBCCDDEEFF0011, 0x2233445566778899)),
            ("xmm1", mk128const(0xAABBCCDDEEFF0011, 0x2233445566778899)),
        ],
        Memory::new(Endian::Little),
    );

    let driver = step_to(driver, 0x4);

    assert_xmm(&driver, "xmm0", 0xAABBCCDDEEFF0011, 0x2233445566778899);
}
