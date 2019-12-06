from unicorn import UcError
from androidemu.emulator import Emulator
from androidemu.java.helpers.native_method import native_method
from androidemu.utils.memory_helpers import read_utf8
from androidemu.java.java_classloader import JavaClassDef
from androidemu.java.java_method_def import java_method_def
from UnicornTraceDebugger import udbg
import logging
logging.basicConfig(level=logging.DEBUG)


@native_method
def hook_aeabi_memclr(mu, address, size):
    # print(f">>> hook memclr: 0x{address:x}, 0x{size:x}")
    mu.mem_write(address, bytes(size))


@native_method
def hook_aeabi_memcpy(mu, dist, source, size):
    # print(f">>> hook memcpy: 0x{dist:x}, 0x{source:x}, 0x{size:x}")
    mem_data = mu.mem_read(source, size)
    mu.mem_write(dist, bytes(mem_data))


@native_method
def hook_sprintf(mu, buffer, format_address, a1, a2):
    format_str = read_utf8(mu, format_address)
    a1_str = read_utf8(mu, a1)
    result = format_str % (a1_str, a2)
    # print(f">>> hook sprintf: {result}")
    mu.mem_write(buffer, bytes((result + '\x00').encode("utf-8")))


class com_sec_udemo_MainActivity(metaclass=JavaClassDef,
                                 jvm_name="com/sec/udemo/MainActivity"):
    @java_method_def(name="getSaltFromJava",
                     signature="(Ljava/lang/String;)Ljava/lang/String;",
                     native=False,
                     args_list=['jstring'])
    def getSaltFromJava(self, mu, arg_str):
        return arg_str.value.value + "salt.."


emulator = Emulator()
emulator.modules.add_symbol_hook(
    "__aeabi_memclr",
    emulator.hooker.write_function(hook_aeabi_memclr) + 1)
emulator.modules.add_symbol_hook(
    "__aeabi_memcpy",
    emulator.hooker.write_function(hook_aeabi_memcpy) + 1)
emulator.modules.add_symbol_hook(
    "sprintf",
    emulator.hooker.write_function(hook_sprintf) + 1)
emulator.java_classloader.add_class(com_sec_udemo_MainActivity)

emulator.load_library("lib/libc.so", do_init=False)
libmod = emulator.load_library("lib/libnative-lib.so", do_init=False)

try:
    dbg = udbg.UnicornDebugger(emulator.mu)
    activity = com_sec_udemo_MainActivity()
    result = emulator.call_symbol(libmod,
                                  "Java_com_sec_udemo_MainActivity_sign_1lv3",
                                  emulator.java_vm.jni_env.address_ptr,
                                  activity, "123")
    print(f">>> result: {result}")
except UcError as e:
    track_list = dbg.get_tracks()
    for el in track_list[-100:-1]:
        print(f">>> dbg trace: 0x{el - 0xcbc66000:x}")
    print(e)
