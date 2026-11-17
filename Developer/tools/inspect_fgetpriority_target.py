#!/usr/bin/env python3
"""分析指定 mefi 内核的重定位符号与优先级调用点。

通过 uv run --with capstone --with vmlinux-to-elf 执行。
结果属于 Developer 自检，不作为独立审计或实机结论。
"""
import argparse
import hashlib
import json
import logging
import struct
from pathlib import Path

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from vmlinux_to_elf.core.kallsyms import KallsymsFinder

EXPECTED_KERNEL = "5946dc4ee4dac4f47dc1404dd9b008b110c8d32dc27c20de049699c7d7110900"
CALLERS = ("sys_getpriority", "sys_setpriority", "sys_ioprio_get", "sys_ioprio_set")


def inspect(image, output):
    """校验指定 Image 并向 output 写分析 JSON/反汇编；返回结果，证据冲突抛出异常。"""
    data = image.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if digest != EXPECTED_KERNEL:
        raise ValueError("内核哈希不匹配；此分析器只接受已指定的 mefi 内核")
    logging.disable(logging.CRITICAL)
    finder = KallsymsFinder(data, 64, False, None)
    # ARM64 Image 的 text_offset 来自目标头部；线性映射基址还须由重定位证据确认。
    text_offset = struct.unpack_from("<Q", data, 8)[0]
    base = 0xFFFFFF8008000000 + text_offset
    reloc = {}
    for pos in range(finder.elf64_rela_start, finder.elf64_rela_end_excl, 24):
        address, info, addend = struct.unpack_from("<QQQ", data, pos)
        if info == 1027:  # R_AARCH64_RELATIVE
            if address in reloc and reloc[address] != addend:
                raise ValueError("同一重定位地址存在冲突")
            reloc[address] = addend
    names = [symbol.name for symbol in finder.symbols]
    if names[:2] != ["_head", "_text"]:
        raise ValueError("目标符号顺序与入口锚点不符")
    count = finder.num_symbols
    candidates = []
    for address, addend in reloc.items():
        if addend != base or reloc.get(address + 8) != base:
            continue
        # 完整表的每个地址均须有真实 relocation；不接受工具错误的回退地址。
        values = [reloc.get(address + index * 8) for index in range(count)]
        if any(value is None for value in values):
            continue
        if any(a > b for a, b in zip(values, values[1:])):
            continue
        if address - base + count * 8 > finder.kallsyms_num_syms__offset:
            continue
        candidates.append((address, values))
    if len(candidates) != 1:
        raise ValueError(f"符号地址表候选不唯一：{len(candidates)}")
    address, values = candidates[0]
    symbols = dict(zip(names, values))
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    output.mkdir(parents=True, exist_ok=True)
    calls = {}
    for name in CALLERS:
        start = symbols[name]
        end = min(value for value in values if value > start)
        if not (0 <= start - base < end - base <= len(data)):
            raise ValueError(f"函数范围无效：{name}")
        instructions = list(md.disasm(data[start - base:end - base], start))
        if sum(insn.size for insn in instructions) != end - start:
            raise ValueError(f"函数无法完整解码：{name}")
        hits = []
        for insn in instructions:
            if insn.mnemonic in ("b", "bl") and insn.op_str == f"#0x{symbols['find_user']:x}":
                hits.append({"address": hex(insn.address), "instruction": insn.bytes.hex(), "kind": insn.mnemonic})
        if len(hits) != 1:
            raise ValueError(f"find_user 调用点不唯一：{name}: {len(hits)}")
        calls[name] = {"address": hex(start), "size": end - start, "calls": hits}
        (output / f"{name}.asm").write_text("\n".join(
            f"{insn.address:x}: {insn.bytes.hex()} {insn.mnemonic} {insn.op_str}"
            for insn in instructions) + "\n")
    result = {"kernel_sha256": digest, "base": hex(base), "symbol_count": count,
              "address_table_offset": hex(address - base), "callers": calls,
              "symbols": {name: hex(symbols[name]) for name in
                          ("find_user", "free_uid", "prctl_get_seccomp", "init_user_ns")},
              "limitations": ["尚未验证运行时 KP 导出与安全卸载", "不是实机或独立审计结论"]}
    (output / "target.json").write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n")
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kernel", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(inspect(args.kernel, args.output), ensure_ascii=False, indent=2))
