use crate::translator::x86::Amd64;
use crate::translator::{Options, Translator};

/// SYSCALL: Fast system call.
/// Per AMD64 manual Vol.3: SYSCALL transfers control to the operating system at the
/// entry point stored in the LSTAR MSR. RCX is loaded with the address of the
/// instruction following SYSCALL, and R11 is loaded with the saved RFLAGS.
/// syscall = 0x0f, 0x05 (2 bytes: two-byte opcode 0F 05h).
/// In Falcon, SYSCALL is translated as an intrinsic.
#[test]
fn syscall_translates() {
    // syscall  =>  0f 05
    let bytes: Vec<u8> = vec![0x0f, 0x05];

    let translator = Amd64::new();
    let result = translator.translate_block(&bytes, 0, &Options::new());
    assert!(
        result.is_ok(),
        "syscall should translate successfully: {:?}",
        result.err()
    );
}
