use super::*;

#[test]
fn punpcklbw_interleave() {
    // punpcklbw xmm0, xmm1 → 66 0f 60 c1
    // nop → 90
    let bytes: Vec<u8> = vec![0x66, 0x0f, 0x60, 0xc1, 0x90];

    // xmm0 lower 8 bytes (LSB first): 01 02 03 04 05 06 07 08
    //   lower qword = 0x0807060504030201
    // xmm1 lower 8 bytes (LSB first): F1 F2 F3 F4 F5 F6 F7 F8
    //   lower qword = 0xF8F7F6F5F4F3F2F1
    // Upper qwords don't matter for the operation (only low 8 bytes used)
    let driver = init_amd64_driver(
        bytes,
        vec![
            ("xmm0", mk128const(0x0000000000000000, 0x0807060504030201)),
            ("xmm1", mk128const(0x0000000000000000, 0xF8F7F6F5F4F3F2F1)),
        ],
        Memory::new(Endian::Little),
    );

    let driver = step_to(driver, 0x4);

    // PUNPCKLBW: interleave bytes from low qwords
    // Result bytes (LSB first):
    //   xmm0[0]=01, xmm1[0]=F1, xmm0[1]=02, xmm1[1]=F2,
    //   xmm0[2]=03, xmm1[2]=F3, xmm0[3]=04, xmm1[3]=F4,
    //   xmm0[4]=05, xmm1[4]=F5, xmm0[5]=06, xmm1[5]=F6,
    //   xmm0[6]=07, xmm1[6]=F7, xmm0[7]=08, xmm1[7]=F8
    //
    // Lower qword (bytes 0-7): 01 F1 02 F2 03 F3 04 F4
    //   = 0xF404F303F202F101
    // Upper qword (bytes 8-15): 05 F5 06 F6 07 F7 08 F8
    //   = 0xF808F707F606F505
    assert_xmm(&driver, "xmm0", 0xF808F707F606F505, 0xF404F303F202F101);
}
