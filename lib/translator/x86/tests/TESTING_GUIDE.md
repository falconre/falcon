# x86/AMD64 Instruction Test Writing Guide

## CRITICAL: Test Against the AMD64 Manual, NOT Falcon's Implementation

All expected values in tests MUST come from the AMD64 Architecture Programmer's Manual
(https://docs.amd.com/v/u/en-US/24594_3.37), NOT from observing what Falcon currently
produces. The purpose of these tests is to reveal bugs in Falcon's lifter.

- Look up each instruction's behavior in the AMD64 manual
- Assert what the manual says the result, flags, and side effects should be
- Do NOT run the test first and write assertions matching Falcon's output
- Failing tests are expected and desired — they found a bug
- Do NOT fix tests or lifter code to make tests pass

## Test Pattern: Executable Instructions

```rust
use super::*;

#[test]
fn instruction_basic() {
    // <instruction mnemonic> <operands>
    // nop
    let bytes: Vec<u8> = vec![0x.., 0x.., 0x90]; // instruction bytes + NOP sentinel

    let driver = init_amd64_driver(
        bytes,
        vec![("rax", il::const_(VALUE, 64))],  // initial register values
        Memory::new(Endian::Little),             // empty memory for reg-only tests
    );

    let driver = step_to(driver, NOP_ADDRESS); // NOP_ADDRESS = byte length of instruction

    // Assert results
    assert_scalar(&driver, "rax", EXPECTED_VALUE);
    assert_flag(&driver, "ZF", 0);
    assert_flag(&driver, "SF", 0);
    assert_flag(&driver, "CF", 0);
    assert_flag(&driver, "OF", 0);
}
```

## Test Pattern: With Memory

```rust
#[test]
fn instruction_with_memory() {
    let bytes: Vec<u8> = vec![...];

    let driver = init_amd64_driver_with_memory(
        bytes,
        vec![("rsi", il::const_(0x1000, 64))],       // registers
        vec![(0x1000, il::const_(0x42, 64))],         // memory: (address, value)
    );

    let driver = step_to(driver, NOP_ADDRESS);

    assert_scalar(&driver, "rax", 0x42);
    // Read memory after execution:
    assert_eq!(load_memory(&driver, 0x1000, 64), NEW_VALUE);
}
```

## Test Pattern: Translation Only (no execution)

```rust
use crate::translator::x86::Amd64;
use crate::translator::{Options, Translator};

#[test]
fn instruction_translates() {
    let bytes: Vec<u8> = vec![...];
    let translator = Amd64::new();
    let result = translator.translate_block(&bytes, 0, &Options::new());
    assert!(result.is_ok());
}
```

## Getting Instruction Bytes

Use nasm:
```bash
echo "BITS 64
<instruction>" | nasm -f bin -o /dev/stdout - | xxd -i
```

Example:
```bash
echo "BITS 64
add rax, rbx" | nasm -f bin -o /dev/stdout - | xxd -i
# Output: 0x48, 0x01, 0xd8
```

Always append `0x90` (NOP) as sentinel byte after the instruction.

## What to Verify by Category

- **Arithmetic** (add, sub, adc, sbb, inc, dec, neg, cmp): result + ZF, SF, CF, OF
- **Logical** (and, or, xor, test): result + ZF, SF, CF=0, OF=0
- **Shifts/rotates** (shl, shr, sar, rol, ror): result + CF, ZF, SF
- **Bit ops** (bt, bts, btr, btc, bsf, bsr): result + CF or ZF
- **Moves** (mov, movsx, movzx, lea): destination value only
- **Conditionals** (cmovcc, setcc): both taken and not-taken paths
- **String ops** (movs, stos, lods, cmps, scas): memory + pointer register updates
- **SSE** (paddq, pxor, pcmpeqb, etc.): 128-bit result via mk128const/assert_xmm

## Edge Cases to Always Test

1. Zero result (sets ZF=1)
2. Maximum unsigned value (0xFFFFFFFFFFFFFFFF for 64-bit)
3. Sign boundary (0x7FFFFFFFFFFFFFFF → 0x8000000000000000)
4. Carry/borrow conditions

## 128-bit Values (SSE)

```rust
// Create a 128-bit constant from two 64-bit halves
let val = mk128const(LO_QWORD, HI_QWORD);

// Assert XMM register value
assert_xmm(&driver, "xmm0", LO_QWORD, HI_QWORD);
```

## Available Helpers

```rust
// Create driver with registers only
init_amd64_driver(bytes, scalars, Memory::new(Endian::Little)) -> Driver

// Create driver with pre-populated memory
init_amd64_driver_with_memory(bytes, scalars, memory_writes) -> Driver

// Step execution to target address
step_to(driver, target_address) -> Driver

// Assertions
assert_scalar(&driver, "rax", expected_u64)
assert_flag(&driver, "ZF", 0_or_1)
assert_xmm(&driver, "xmm0", lo_u64, hi_u64)

// Read memory
load_memory(&driver, address, bits) -> u64

// 128-bit constant
mk128const(lo, hi) -> il::Constant
```
