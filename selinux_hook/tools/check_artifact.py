#!/usr/bin/env python3
"""检查探索 KPM 的 ELF、入口、导入和 AArch64 寄存器使用。需 pyelftools、capstone。"""
import argparse
import hashlib
import json
import re
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from elftools.elf.elffile import ELFFile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('kpm', type=Path, nargs='+')
    args = parser.parse_args()
    for path in args.kpm:
        with path.open('rb') as stream:
            elf = ELFFile(stream)
            assert elf['e_type'] == 'ET_REL' and elf['e_machine'] == 'EM_AARCH64'
            imports = [s.name for s in elf.get_section_by_name('.symtab').iter_symbols()
                       if s.name and s['st_shndx'] == 'SHN_UNDEF']
            assert not set(imports) & {'memcpy', 'memset', 'snprintf', '__stack_chk_fail'}, imports
            sections = {s.name for s in elf.iter_sections()}
            assert {'.kpm.init', '.kpm.exit', '.kpm.ctl0', '.kpm.info', '.data.re_offsets'} <= sections
            decoded = 0
            md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
            for section in elf.iter_sections():
                if not section['sh_flags'] & 4:
                    continue
                instructions = list(md.disasm(section.data(), section['sh_addr']))
                assert sum(i.size for i in instructions) == section['sh_size'], section.name
                for inst in instructions:
                    assert not re.search(r'\b(?:[qvdsbh][0-9]+|x18|w18)\b', inst.op_str), (inst.mnemonic, inst.op_str)
                decoded += section['sh_size']
            print(json.dumps({'file': path.name, 'size': path.stat().st_size,
                              'sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
                              'imports': imports, 'decoded_executable_bytes': decoded}, ensure_ascii=False))


if __name__ == '__main__':
    main()
