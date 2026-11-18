#!/usr/bin/env python3
"""执行指定 mefi 镜像的实际 KP 指令，核验远距离跳板及回调 LR 帧契约。

依赖 unicorn；仅仿真 hook_prepare 和 _transit4，不执行真实文本补丁或 RCU 同步。
"""
import argparse
import hashlib
import json
import struct
from pathlib import Path

from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE
from unicorn.arm64_const import UC_ARM64_REG_X0, UC_ARM64_REG_X16, UC_ARM64_REG_X30, UC_ARM64_REG_PC, UC_ARM64_REG_SP

EXPECTED = "5946dc4ee4dac4f47dc1404dd9b008b110c8d32dc27c20de049699c7d7110900"
KP_BASE = 0xFFFFFF936AA03000
ORIGINAL = 0xFFFFFF916B631BF4
WRAPPER = 0xFFFFFF936B1DCEE8
CHAIN = 0xFFFFFF936B500000
STACK = 0xFFFFFF936B600000
STOP = 0xFFFFFF936B700000


def machine(data):
    """建立只含目标 KP 字节和诊断内存页的 ARM64 实例，返回 Uc。"""
    cpu = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    block = data[0x269D000:0x2706360]
    cpu.mem_map(KP_BASE, (len(block) + 4095) & ~4095)
    cpu.mem_write(KP_BASE, block)
    cpu.mem_map(ORIGINAL & ~4095, 4096)
    cpu.mem_write(ORIGINAL, data[0x1B1BF4:0x1B1BF4 + 32])
    for address in (CHAIN, STACK, STOP):
        cpu.mem_map(address, 4096)
    cpu.reg_write(UC_ARM64_REG_SP, STACK + 0x800)
    return cpu


def verify(image):
    """核验目标哈希并执行两段 KP 函数；返回证据，断言不符即失败。"""
    data = image.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if digest != EXPECTED:
        raise ValueError("只接受已指定的 mefi 内核字节")
    cpu = machine(data)
    cpu.mem_write(CHAIN, struct.pack("<QQQQ", ORIGINAL, ORIGINAL, WRAPPER, CHAIN + 0x58))
    cpu.reg_write(UC_ARM64_REG_X0, CHAIN)
    cpu.reg_write(UC_ARM64_REG_X30, STOP)
    cpu.emu_start(KP_BASE + 0x5E00, STOP, count=10000)
    assert cpu.reg_read(UC_ARM64_REG_PC) == STOP
    assert cpu.reg_read(UC_ARM64_REG_X0) == 0
    count, relocated = struct.unpack("<II", cpu.mem_read(CHAIN + 0x20, 8))
    trampoline = bytes(cpu.mem_read(CHAIN + 0x40, 16))
    # LDR X17, #8; BR X17; 完整 64 位地址，不丢失远距离地址位。
    assert count == 4
    assert trampoline == struct.pack("<IIQ", 0x58000051, 0xD61F0220, WRAPPER)

    cpu = machine(data)
    caller = 0xFFFFFF916B63C544
    origin_stub = STOP + 0x100
    after_stub = STOP + 0x200
    user = 0x123400
    cpu.mem_write(origin_stub, struct.pack("<I", 0xD65F03C0))
    cpu.mem_write(after_stub, struct.pack("<I", 0xD65F03C0))
    cpu.mem_write(CHAIN + 0x18, struct.pack("<Q", origin_stub))
    cpu.mem_write(CHAIN + 0xE8, struct.pack("<I", 1))
    cpu.mem_write(CHAIN + 0xEC, b"\x01")
    cpu.mem_write(CHAIN + 0x200, struct.pack("<Q", after_stub))
    cpu.reg_write(UC_ARM64_REG_X16, CHAIN)
    cpu.reg_write(UC_ARM64_REG_X0, 10002)
    cpu.reg_write(UC_ARM64_REG_X30, caller)
    observed = {}

    def observe(uc, address, size, data):
        """仅替代外部原函数和模块回调；实际 KP 帧和调度由目标指令生成。"""
        del size, data
        if address == origin_stub:
            uc.reg_write(UC_ARM64_REG_X0, user)
        elif address == after_stub:
            args = uc.reg_read(UC_ARM64_REG_X0)
            lr = struct.unpack("<Q", uc.mem_read(args - 0x40, 8))[0]
            ret = struct.unpack("<Q", uc.mem_read(args + 0x50, 8))[0]
            uid = struct.unpack("<Q", uc.mem_read(args + 0x58, 8))[0]
            assert lr == caller and ret == user and uid == 10002
            observed.update(caller=hex(lr), uid=uid, original_return=ret, saved_lr_back=0x40)

    cpu.hook_add(UC_HOOK_CODE, observe)
    cpu.emu_start(KP_BASE + 0x4780, caller, count=10000)
    assert cpu.reg_read(UC_ARM64_REG_PC) == caller
    assert cpu.reg_read(UC_ARM64_REG_X0) == user and observed
    return {"kernel_sha256": digest, "hook_prepare_rc": 0, "distance_bytes": WRAPPER - ORIGINAL,
            "trampoline": trampoline.hex(), "relocated_words": relocated, "frame": observed,
            "limitations": ["未执行 hotpatch、RCU 等待或实际模块加载", "不是独立审计结论"]}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kernel", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = verify(args.kernel)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n")
    print(json.dumps(result, ensure_ascii=False, indent=2))
