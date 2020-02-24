from capstone import *

# imul
CODE = b"\xf7\xe9"

# ja
CODE = b"\x77\x04"

# jmp
CODE = b"\xe9\x0c\x00\x00\x00"

# ret
CODE = b"\xc3"

# ret imm
CODE = b"\xc2\x14\x00"

# repe stosd
CODE = b"\xf3\xab"

# lea esp, [ebc - 0xc]
CODE = b"\x8d\x65\xf4"

# int 0x80
CODE = b"\xcd\x80"

# mov eax, dword [gs:0x14]
CODE = b"\x65\xa1\x14\x00\x00\x00"

CODE = "\x66\x0f\x73\xfa\x07"
md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True
d = md.disasm(CODE, 0x1000).next()
print(d.mnemonic, d.op_str)



from capstone import *
CODE = b"\x66\x0f\x73\xfa\x07"
md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True
d = list(md.disasm(CODE, 0x1000))[0]
print(d.mnemonic, d.op_str, d.operands[1].size)