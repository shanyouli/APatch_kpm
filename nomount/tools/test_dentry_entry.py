#!/usr/bin/env python3
"""执行生产 d_set_d_op 识别器；仅宿主核验，不加载 KPM 或执行目标指令。"""

import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
# 用户 miuiportspatched.img 的真实 d_set_d_op 前九条；参考偏移取自
# 该入口的 d_op 检查和后续写回，并以 __dentry_kill 的 d_op→prune 链核对。
TARGET_WORDS = (0xA9BD7BFD, 0xF9000BF5, 0xA9024FF4, 0x910003FD,
                0xF9403008, 0xAA1E03F5, 0xAA0003F3, 0xAA0103F4, 0xB4000088)
TARGET_OFFSET = 96


def function(text, name):
    """从 text 提取具名生产函数定义并返回文本；缺失或重名时拒绝。

    仅用于本文件列出的静态函数，不改函数体或在生产代码中插桩。
    """
    matches = list(re.finditer(r'^static [^\n]*\b' + re.escape(name) + r'\([^;]*?\)\s*\{', text, re.M))
    if len(matches) != 1:
        raise ValueError(f'生产函数定义不唯一: {name}')
    match = matches[0]
    end, depth = match.end(), 1
    while depth:
        depth += (text[end] == '{') - (text[end] == '}')
        end += 1
    return text[match.start():end] + '\n'


def main():
    """读取当前生产代码并运行正反例；返回0，编译/断言失败传播异常。

    使用已安装宿主Clang和临时输出目录；不下载工具，不生成KPM。
    可选 --output 保存本次源码指纹与入口证据，已存在时拒绝覆盖。
    """
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    compiler = shutil.which('clang')
    if not compiler:
        raise RuntimeError('没有已安装的宿主Clang，未执行验证')
    utils = (ROOT / 'kpm_utils.h').read_text().split('// instruction\n', 1)[1].rsplit('#endif', 1)[0]
    offsets = (ROOT / 'nomount/nm_offsets.c').read_text()
    names = ('nm_load', 'nm_store', 'nm_move', 'nm_rule_entry_save', 'nm_argument_changed', 'nm_find_dentry_ops')
    source = r'''
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
'''
    source += utils + ''.join(function(offsets, name) for name in names)
    source += 'static const uint32_t target[9] = {' + ','.join(hex(word) for word in TARGET_WORDS) + '};\n'
    source += r'''
int main(void) {
  uint32_t code[17];
  for (unsigned i = 0; i < 17; i++) code[i] = 0xd503201fU;
  memcpy(code, target, sizeof(target));
  assert(nm_find_dentry_ops(code) == 96);
  // 每次单独还原真实入口；不能靠更远的STR或CBNZ接受损坏的参数来源。
  for (unsigned i = 0; i < 9; i++) {
    uint32_t saved = code[i]; code[i] = 0xd503201fU;
    assert(nm_find_dentry_ops(code) < 0); code[i] = saved;
  }
  // 来源寄存器、64位宽度、前向守卫目标分别拒绝。
  const struct { unsigned index; uint32_t word; } bad[] = {
    {0, 0x94000001U}, {1, 0xc8087c83U}, {2, 0xa94007e8U},
    {4, 0xf9403028U}, {4, 0xb9403008U}, {4, 0xf9403009U},
    {5, 0xaa0203f5U}, {6, 0xaa0103f3U}, {6, 0x2a0003f3U},
    {7, 0xaa0003f4U}, {7, 0x2a0103f4U},
    {8, 0x34000088U}, {8, 0xb4000089U}, {8, 0xb4000068U},
    {8, 0xb4000060U}, {8, 0xb4ffff88U}
  };
  for (unsigned i = 0; i < sizeof(bad)/sizeof(bad[0]); i++) {
    uint32_t saved = code[bad[i].index]; code[bad[i].index] = bad[i].word;
    assert(nm_find_dentry_ops(code) < 0); code[bad[i].index] = saved;
  }
  // 合法偏移从LDR立即数取得；不把本目标96写入生产代码。
  code[4] = 0xf9403808U;
  assert(nm_find_dentry_ops(code) == 112);
  memcpy(code, target, sizeof(target));
  memmove(code + 1, code, sizeof(target)); code[0] = 0xd503233fU;
  assert(nm_find_dentry_ops(code) == 96);
  // 既有GCC短入口和Clang CBNZ/STR形态保持，不改旧断言。
  for (unsigned i = 0; i < 17; i++) code[i] = 0xd503201fU;
  code[0] = 0xf9403008U; code[1] = 0xb4000088U;
  assert(nm_find_dentry_ops(code) == 96);
  code[1] = 0xb5000088U; code[2] = 0xf9003001U;
  assert(nm_find_dentry_ops(code) == 96);
  // 新分支只需要九条；保护页证明不会读到较远的写回。
  long page = sysconf(_SC_PAGESIZE); assert(page > 128);
  unsigned char* pages = mmap(NULL, page*2, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANON, -1, 0);
  assert(pages != MAP_FAILED && !mprotect(pages + page, page, PROT_NONE));
  uint32_t* entry = (void*)(pages + page - sizeof(target));
  memcpy(entry, target, sizeof(target)); assert(nm_find_dentry_ops(entry) == 96);
  entry = (void*)(pages + page - sizeof(target) - 4);
  entry[0] = 0xd503233fU; memcpy(entry + 1, target, sizeof(target));
  assert(nm_find_dentry_ops(entry) == 96);
  // 未匹配时原有16条失败窗口也不能越界。
  entry = (void*)(pages + page - 16*4);
  for (unsigned i = 0; i < 16; i++) entry[i] = 0xd503201fU;
  assert(nm_find_dentry_ops(entry) < 0);
  assert(!munmap(pages, page*2));
  puts("dentry entry checks passed");
  return 0;
}
'''
    with tempfile.TemporaryDirectory(prefix='nomount-dentry-entry-') as directory:
        path = Path(directory)
        (path / 'test.c').write_text(source)
        command = [compiler, '-Wall', '-Werror', '-Wno-unused-function', '-fsanitize=address,undefined',
                   str(path / 'test.c'), '-o', str(path / 'test')]
        subprocess.run(command, check=True)
        subprocess.run([str(path / 'test')], check=True)
    if args.output:
        receipt = {'scope': 'Developer宿主生产识别器自检；不是独立审计或设备加载结论',
                   'production_sha256': hashlib.sha256(offsets.encode()).hexdigest(),
                   'utils_sha256': hashlib.sha256((ROOT / 'kpm_utils.h').read_bytes()).hexdigest(),
                   'tool_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                   'fixture_words': list(TARGET_WORDS), 'reference_offset': TARGET_OFFSET,
                   'new_prefix_words': len(TARGET_WORDS), 'legacy_window_words': 16}
        with args.output.open('x') as output:
            json.dump(receipt, output, ensure_ascii=False, indent=2)
            output.write('\n')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
