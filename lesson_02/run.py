from unicorn import Uc, UcError, UC_ARCH_ARM, UC_MODE_THUMB, UC_HOOK_CODE, UC_HOOK_MEM_UNMAPPED
from unicorn.arm_const import UC_ARM_REG_SP, UC_ARM_REG_R0, UC_ARM_REG_R2, UC_ARM_REG_PC


def hook_code(uc, address, size, user_data):
    print(f">>> Tracing instruction at 0x{address:x}, run size = 0x{size:x}")


def hook_memory(uc, access, address, size, value, user_data):
    pc = uc.reg_read(UC_ARM_REG_PC)
    print(f">>> Memory err pc:0x{pc:x} address:0x{address:x}, size:0x{size:x}")


a1 = b'123'
mu = Uc(UC_ARCH_ARM, UC_MODE_THUMB)

# 分配 so 内存
image_base = 0x0
image_size = 0x10000 * 8
mu.mem_map(image_base, image_size)
with open("libnative-lib.so", "rb") as f:
    sofile = f.read()
    mu.mem_write(image_base, sofile)

# 分配 Stack 内存
stack_base = 0xA0000
stack_size = 0x10000 * 3
stack_top = stack_base + stack_size - 0x4
mu.mem_map(stack_base, stack_size)
mu.reg_write(UC_ARM_REG_SP, stack_top)

# 分配数据内存
data_base = 0xF0000
data_size = 0x10000 * 3
mu.mem_map(data_base, data_size)
mu.mem_write(data_base, a1)
mu.reg_write(UC_ARM_REG_R0, data_base)

# 修复 Got 表
mu.mem_write(image_base + 0x1EDB0, b"\xD9\x98\x00\x00")

# 设置 Hook
mu.hook_add(UC_HOOK_CODE, hook_code, None)
mu.hook_add(UC_HOOK_MEM_UNMAPPED, hook_memory, None)

# 设置需要 Run 的函数地址
func_start = image_base + 0x9B68 + 0x1
func_end = image_base + 0x9C2C

try:
    mu.emu_start(func_start, func_end)
    r2 = mu.reg_read(UC_ARM_REG_R2)
    result = mu.mem_read(r2, 16)
    print(result.hex())
except UcError as e:
    print(f"UC run error {e}")
