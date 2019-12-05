from keystone import Ks, KS_ARCH_ARM, KS_MODE_ARM

asm = Ks(KS_ARCH_ARM, KS_MODE_ARM)
code = '''mov r0, #0x37;
sub r1, r2, r3'''
asm_code = asm.asm(code)
print(asm_code)
print(bytes(asm_code[0]))
