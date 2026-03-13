use super::*;

#[test]
fn pshufd_reverse() {
    // pshufd xmm0, xmm1, 0x1B → 66 0f 70 c1 1b
    // nop → 90
    // imm8 = 0x1B = 0b00_01_10_11 reverses dword order
    let bytes: Vec<u8> = vec![0x66, 0x0f, 0x70, 0xc1, 0x1b, 0x90];

    // xmm1 dwords: dword3=0x44444444 dword2=0x33333333 dword1=0x22222222 dword0=0x11111111
    // upper 64 bits (lo param) = dword3:dword2 = 0x44444444_33333333
    // lower 64 bits (hi param) = dword1:dword0 = 0x22222222_11111111
    let driver = init_amd64_driver(
        bytes,
        vec![
            ("xmm0", mk128const(0x0000000000000000, 0x0000000000000000)),
            ("xmm1", mk128const(0x4444444433333333, 0x2222222211111111)),
        ],
        Memory::new(Endian::Little),
    );

    let driver = step_to(driver, 0x5);

    // imm8 = 0b00_01_10_11:
    //   dest[31:0]   = src dword 3 = 0x44444444
    //   dest[63:32]  = src dword 2 = 0x33333333
    //   dest[95:64]  = src dword 1 = 0x22222222
    //   dest[127:96] = src dword 0 = 0x11111111
    // Result: upper = 0x11111111_22222222, lower = 0x33333333_44444444
    assert_xmm(&driver, "xmm0", 0x1111111122222222, 0x3333333344444444);
}

#[test]
fn pshufd_broadcast_low() {
    // pshufd xmm0, xmm1, 0x00 → 66 0f 70 c1 00
    // nop → 90
    // imm8 = 0x00 = 0b00_00_00_00 broadcasts dword 0 to all positions
    let bytes: Vec<u8> = vec![0x66, 0x0f, 0x70, 0xc1, 0x00, 0x90];

    let driver = init_amd64_driver(
        bytes,
        vec![
            ("xmm0", mk128const(0x0000000000000000, 0x0000000000000000)),
            ("xmm1", mk128const(0xDDDDDDDDCCCCCCCC, 0xBBBBBBBBAAAAAAAA)),
        ],
        Memory::new(Endian::Little),
    );

    let driver = step_to(driver, 0x5);

    // imm8 = 0b00_00_00_00: all four dest dwords = src dword 0 = 0xAAAAAAAA
    // Result: all dwords are 0xAAAAAAAA
    // upper = 0xAAAAAAAA_AAAAAAAA, lower = 0xAAAAAAAA_AAAAAAAA
    assert_xmm(&driver, "xmm0", 0xAAAAAAAAAAAAAAAA, 0xAAAAAAAAAAAAAAAA);
}
