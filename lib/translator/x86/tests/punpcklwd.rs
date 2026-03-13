use super::*;

#[test]
fn punpcklwd_interleave() {
    // punpcklwd xmm0, xmm1 → 66 0f 61 c1
    // nop → 90
    let bytes: Vec<u8> = vec![0x66, 0x0f, 0x61, 0xc1, 0x90];

    // xmm0 lower qword words (LSB first): 0001, 0002, 0003, 0004
    //   lower qword = 0x0004000300020001
    // xmm1 lower qword words (LSB first): AA00, BB00, CC00, DD00
    //   lower qword = 0xDD00CC00BB00AA00
    // Upper qwords are unused by the instruction
    let driver = init_amd64_driver(
        bytes,
        vec![
            ("xmm0", mk128const(0x0000000000000000, 0x0004000300020001)),
            ("xmm1", mk128const(0x0000000000000000, 0xDD00CC00BB00AA00)),
        ],
        Memory::new(Endian::Little),
    );

    let driver = step_to(driver, 0x4);

    // PUNPCKLWD: interleave 16-bit words from low qwords
    // Result words (LSB first):
    //   xmm0_w0=0001, xmm1_w0=AA00,
    //   xmm0_w1=0002, xmm1_w1=BB00,
    //   xmm0_w2=0003, xmm1_w2=CC00,
    //   xmm0_w3=0004, xmm1_w3=DD00
    //
    // Lower qword = word3:word2:word1:word0 = BB00:0002:AA00:0001
    //   = 0xBB000002AA000001
    // Upper qword = word7:word6:word5:word4 = DD00:0004:CC00:0003
    //   = 0xDD000004CC000003
    assert_xmm(&driver, "xmm0", 0xDD000004CC000003, 0xBB000002AA000001);
}
