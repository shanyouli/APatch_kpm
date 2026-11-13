#!/usr/bin/env python3
"""只读反汇编选定 ARM64 Image 的具名锚点；不改镜像、不操作设备。

符号文件使用 Image 相对偏移。优先使用已安装 capstone，否则尝试本机
Clang 同目录的 libLTO 反汇编接口；不下载依赖，输出文件拒绝覆盖。
"""

import argparse
import ctypes
from pathlib import Path
import re
import shutil
import struct
import subprocess


class Disassembler:
    """封装已安装的 ARM64 反汇编器；初始化失败抛异常，不自行安装资源。"""

    def __init__(self):
        """无参数；优先 capstone，否则初始化本机 LLVM LTO 后端。"""
        try:
            from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
            self.capstone = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
            self.lib = None
            return
        except ImportError:
            self.capstone = None
        clang = shutil.which("clang")
        if not clang:
            raise RuntimeError("没有已安装的 capstone 或 Clang/libLTO")
        library = Path(clang).resolve().parent.parent / "lib/libLTO.dylib"
        if not library.is_file() and shutil.which("xcrun"):
            compiler = subprocess.check_output(["xcrun", "--find", "clang"], text=True, timeout=5).strip()
            library = Path(compiler).resolve().parent.parent / "lib/libLTO.dylib"
        self.lib = ctypes.CDLL(str(library))
        self.lib.lto_initialize_disassembler()
        self.lib.LLVMCreateDisasm.argtypes = [ctypes.c_char_p, ctypes.c_void_p, ctypes.c_int,
                                            ctypes.c_void_p, ctypes.c_void_p]
        self.lib.LLVMCreateDisasm.restype = ctypes.c_void_p
        self.ctx = self.lib.LLVMCreateDisasm(b"aarch64-unknown-linux-gnu", None, 0, None, None)
        if not self.ctx:
            raise RuntimeError("本机 LLVM 没有可用的 AArch64 反汇编上下文")
        self.lib.LLVMDisasmInstruction.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint64,
                                                 ctypes.c_uint64, ctypes.c_char_p, ctypes.c_size_t]
        self.lib.LLVMDisasmInstruction.restype = ctypes.c_size_t
        self.lib.LLVMDisasmDispose.argtypes = [ctypes.c_void_p]

    def instruction(self, data, address):
        """反汇编 address 处四字节 data；返回文本，不能解析时显式返回 .word。"""
        if self.capstone:
            result = next(iter(self.capstone.disasm(data, address)), None)
            if result:
                return result.mnemonic + " " + result.op_str
        else:
            source = ctypes.create_string_buffer(data)
            text = ctypes.create_string_buffer(512)
            if self.lib.LLVMDisasmInstruction(self.ctx, source, len(data), address, text, len(text)):
                return text.value.decode().strip()
        return f".word 0x{int.from_bytes(data, 'little'):08x}"

    def close(self):
        """无参数，无返回值；释放本工具的反汇编上下文。"""
        if self.lib and self.ctx:
            self.lib.LLVMDisasmDispose(self.ctx)
            self.ctx = None


def load_symbols(path):
    """读取 path 中相对偏移符号；返回列表，忽略工具日志但保留重名与别名。"""
    symbols = []
    for line in path.read_text().splitlines():
        match = re.fullmatch(r"(?:0x)?([0-9a-fA-F]+)\s+([A-Za-z])\s+(\S+)", line)
        if match:
            symbols.append((int(match[1], 16), match[2], match[3]))
    if not symbols:
        raise ValueError("符号输入没有可解析的条目")
    return symbols


def main():
    """解析参数并保存锚点反汇编；返回 0，缺锚点/越界/覆盖输出时抛异常。"""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", type=Path, required=True)
    parser.add_argument("--symbols", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--anchor", action="append", required=True)
    parser.add_argument("--count", type=int, default=96)
    args = parser.parse_args()
    if not 1 <= args.count <= 1024:
        raise ValueError("反汇编长度必须在 1～1024 条之间")
    data = args.image.read_bytes()
    symbols = load_symbols(args.symbols)
    by_address = {}
    for address, kind, name in symbols:
        by_address.setdefault(address, []).append(name)
    args.out.mkdir(parents=True, exist_ok=True)
    dis = Disassembler()
    try:
        for anchor in args.anchor:
            matches = [(address, name) for address, kind, name in symbols
                       if kind.lower() == "t" and (name == anchor or name.startswith(anchor + "$")
                           or name.startswith(anchor + ".")) and ".cfi" not in name]
            if not matches:
                raise ValueError(f"锚点不可见：{anchor}")
            for address, name in matches:
                next_address = min((a for a in by_address if a > address), default=len(data))
                end = min(address + args.count * 4, next_address, len(data))
                if address < 0 or end <= address or address % 4:
                    raise ValueError(f"锚点范围无效：{name}")
                lines = [f"# {name} @ Image+0x{address:x}; end=0x{end:x}\n"]
                for pc in range(address, end - 3, 4):
                    word = struct.unpack_from("<I", data, pc)[0]
                    text = dis.instruction(data[pc:pc + 4], pc)
                    note = ""
                    if word & 0x7C000000 == 0x14000000:
                        immediate = word & 0x03FFFFFF
                        if immediate & 0x02000000:
                            immediate -= 0x04000000
                        target = pc + immediate * 4
                        note = f" ; Image+0x{target:x} " + ",".join(by_address.get(target, []))
                    lines.append(f"0x{pc:08x}: {word:08x}  {text}{note}\n")
                target = args.out / (name + ".asm")
                with target.open("x") as output:
                    output.writelines(lines)
                print(f"{name}: Image+0x{address:x}, {(end-address)//4} 条 -> {target.name}")
    finally:
        dis.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
