from unicorn import Uc, UcError, UC_ARCH_ARM, UC_MODE_THUMB, UC_HOOK_CODE
from unicorn.arm_const import UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3

ARM_CODE = b'7\x00\xa0\xe3\x03\x10B\xe0'


def hook_code(uc, address, size, user_data):
    print(f">>> Tracing instruction at 0x{address:x}, run size = 0x{size:x}")


def run():
    print("Start emulate ARM...")
    try:
        # 创建虚拟机
        mu = Uc(UC_ARCH_ARM, UC_MODE_THUMB)

        # 分配内存
        ADDRESS = 0x10000
        mu.mem_map(ADDRESS, 0x1000)
        mu.mem_write(ADDRESS, ARM_CODE)

        # 写寄存器
        mu.reg_write(UC_ARM_REG_R0, 0x1234)
        mu.reg_write(UC_ARM_REG_R2, 0x6789)
        mu.reg_write(UC_ARM_REG_R3, 0x3333)

        # Hook 代码
        mu.hook_add(UC_HOOK_CODE, hook_code, None, ADDRESS, ADDRESS + 0x1000)

        # 启动虚拟机
        mu.emu_start(ADDRESS, ADDRESS + len(ARM_CODE))

        # 获取结果
        r0 = mu.reg_read(UC_ARM_REG_R0)
        r1 = mu.reg_read(UC_ARM_REG_R1)
        print(f">>> R0 = 0x{r0:x}")
        print(f">>> R1 = 0x{r1:x}")

    except UcError as e:
        print(f"Emulate error: {e}")


if __name__ == '__main__':
    run()
