use crate::translator::x86::Amd64;
use crate::translator::{Options, Translator};

/// SYSENTER: Fast call to privilege level 0 system procedure.
/// Per AMD64 manual Vol.3: SYSENTER transfers control to a fixed entry point
/// specified by MSRs (IA32_SYSENTER_CS, IA32_SYSENTER_EIP, IA32_SYSENTER_ESP).
/// sysenter = 0x0f, 0x34 (2 bytes: two-byte opcode 0F 34h).
/// In Falcon, SYSENTER is translated as an intrinsic.
#[test]
fn sysenter_translates() {
    // sysenter  =>  0f 34
    let bytes: Vec<u8> = vec![0x0f, 0x34];

    let translator = Amd64::new();
    let result = translator.translate_block(&bytes, 0, &Options::new());
    assert!(
        result.is_ok(),
        "sysenter should translate successfully: {:?}",
        result.err()
    );
}
