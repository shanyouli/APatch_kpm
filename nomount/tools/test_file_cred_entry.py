#!/usr/bin/env python3
"""核验file_ns_capable保存寄存器入口；仅宿主生产函数自检，不构建或加载KPM。"""

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

sys.dont_write_bytecode = True
from test_dentry_entry import function

ROOT = Path(__file__).resolve().parents[2]
# 来自用户miuiportspatched.img，Image+0x1ae4b0；22条窗口止于首次凭据读取。
TARGET_WORDS = (
    0xD10143FF, 0xA9017BFD, 0xA9025FF8, 0xA90357F6, 0xA9044FF4, 0x910043FD,
    0x2A0203F3, 0xAA0103F4, 0x7100985F, 0xAA0003F5, 0x54000083, 0x90011768,
    0x3970FD09, 0x34000589, 0x7100967F, 0x540006C8, 0xD000D2D6, 0x913E82D6,
    0xF94002D7, 0xEB1602FF, 0x54000380, 0xF9404AB5,
)


def main():
    """读取当前生产函数并执行正反例；成功返回0，任何编译/断言失败传播异常。

    可选--output排他保存本次来源及窗口回执；使用已有宿主Clang和临时目录，
    不依赖本地镜像语料、不修改现有Oracle，不把直接调用桩视为真实LSM/CFI。
    """
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    compiler = shutil.which('clang')
    if not compiler:
        raise RuntimeError('没有已安装的宿主Clang，未执行验证')
    offsets = (ROOT / 'nomount/nm_offsets.c').read_text()
    utils = (ROOT / 'kpm_utils.h').read_text().split('// instruction\n', 1)[1].rsplit('#endif', 1)[0]
    names = ('nm_load', 'nm_store', 'nm_move', 'nm_load_at', 'nm_move32', 'nm_add_at', 'nm_compare',
             'nm_pair_store_at', 'nm_rule_entry_save', 'nm_argument_changed',
             'nm_find_saved_file_cred', 'nm_find_file_cred')
    source = r'''
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
'''
    source += utils + ''.join(function(offsets, name) for name in names)
    source += 'static const uint32_t original[] = {' + ','.join(hex(word) for word in TARGET_WORDS) + '};\n'
    source += r'''
int main(void) {
  uint32_t code[23];
  memcpy(code, original, sizeof(original));
  assert(nm_find_saved_file_cred(code) == 144);
  assert(nm_find_file_cred(code) == 144);
  // 所有22条均参与证据链；调用、原子状态写回、未知指令不能被跳过。
  const uint32_t replacements[] = {0xd503201fU, 0x94000000U, 0xc8157c83U};
  for (unsigned r = 0; r < sizeof(replacements) / sizeof(replacements[0]); r++) {
    for (unsigned i = 0; i < 22; i++) {
      uint32_t saved = code[i]; code[i] = replacements[r];
      assert(nm_find_saved_file_cred(code) < 0);
      assert(nm_find_file_cred(code) < 0); code[i] = saved;
    }
  }
  const struct { unsigned index; uint32_t word; } bad[] = {
    {0, 0x510143ffU}, {0, 0xd10143e0U}, {1, 0xa90103fdU},
    {5, 0x110043fdU}, {6, 0xaa0203f3U}, {6, 0x2a0103f3U}, {7, 0xaa0003f4U},
    {8, 0xf100985fU}, {8, 0x7100987fU}, {8, 0x7100945fU},
    {9, 0xaa0103f5U}, {9, 0x2a0003f5U}, {10, 0x54000082U},
    {10, 0x540000a3U}, {10, 0x54ffffe3U}, {11, 0x90011775U},
    {12, 0x3970fd29U}, {12, 0x7970fd09U}, {12, 0x3970fd15U},
    {13, 0xb4000589U}, {13, 0x34000109U}, {13, 0x34ffffe9U},
    {14, 0x7100969fU}, {14, 0x7100927fU}, {15, 0x540006c9U}, {15, 0x540000c8U},
    {16, 0xd000d2d5U}, {17, 0x113e82d6U}, {17, 0x913e82b6U}, {17, 0x913e82d5U},
    {18, 0xf94002b7U}, {18, 0xb94002d7U}, {18, 0xf94002d5U},
    {19, 0x6b1602ffU}, {19, 0xeb1502ffU}, {19, 0xeb1602bfU},
    {20, 0x54000381U}, {20, 0x54000020U}, {20, 0x54ffffe0U},
    {21, 0xf9404a95U}, {21, 0xb9404ab5U}, {21, 0xf9404ab4U}, {21, 0xf8494eb5U},
  };
  for (unsigned i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
    unsigned at = bad[i].index; uint32_t saved = code[at]; code[at] = bad[i].word;
    assert(nm_find_saved_file_cred(code) < 0);
    assert(nm_find_file_cred(code) < 0); code[at] = saved;
  }
  // 位移取自LDR，不写死144；0与其它合法位移沿旧字段契约接受。
  const unsigned offsets[] = {0, 8, 144, 200, 32760};
  for (unsigned i = 0; i < sizeof(offsets) / sizeof(offsets[0]); i++) {
    code[21] = 0xf94002b5U | ((offsets[i] / 8) << 10);
    assert(nm_find_file_cred(code) == (int)offsets[i]);
  }
  memcpy(code, original, sizeof(original));
  memmove(code + 1, code, sizeof(original)); code[0] = 0xd503233fU;
  assert(nm_find_file_cred(code) == 144);
  // 旧直接字段读取、GCC告警分支和BTI路径原样执行，不改现有测试断言。
  uint32_t direct[] = {0xf9404800U};
  assert(nm_find_file_cred(direct) == 144);
  uint32_t gcc[12];
  for (unsigned i = 0; i < 12; i++) gcc[i] = 0xd503201fU;
  gcc[0] = 0xa9bf7bfdU; gcc[1] = 0x7100945fU; gcc[2] = 0x910003fdU;
  gcc[3] = 0x54000109U; gcc[11] = 0xf9404800U;
  assert(nm_find_file_cred(gcc) == 144);
  gcc[3] ^= 1U; assert(nm_find_file_cred(gcc) < 0);
  uint32_t bti[] = {0xd503245fU, 0x7100a45fU, 0x54000182U, 0xd503233fU,
    0xa9bf7bfdU, 0xa9014ff4U, 0xa9014ff4U, 0xa9014ff4U, 0xa9014ff4U, 0x910003fdU,
    0x90000008U, 0xf9400116U, 0xb4000056U, 0xf9404815U};
  assert(nm_find_file_cred(bti) == 144);
  bti[12] = 0x34000056U; assert(nm_find_file_cred(bti) < 0);
  // 保护页：新分支22条，含PAC23条；旧失败8条与旧成功入口不扩大。
  long page = sysconf(_SC_PAGESIZE); assert(page > 256);
  unsigned char* pages = mmap(NULL, page * 2, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
  assert(pages != MAP_FAILED && !mprotect(pages + page, page, PROT_NONE));
  uint32_t* entry = (void*)(pages + page - sizeof(original));
  memcpy(entry, original, sizeof(original)); assert(nm_find_file_cred(entry) == 144);
  for (unsigned i = 0; i < 22; i++) {
    uint32_t saved = entry[i]; entry[i] = 0xd503201fU;
    assert(nm_find_file_cred(entry) < 0); entry[i] = saved;
  }
  entry = (void*)(pages + page - sizeof(original) - 4);
  entry[0] = 0xd503233fU; memcpy(entry + 1, original, sizeof(original));
  assert(nm_find_file_cred(entry) == 144);
  entry = (void*)(pages + page - 8 * 4);
  for (unsigned i = 0; i < 8; i++) entry[i] = 0xd503201fU;
  assert(nm_find_file_cred(entry) < 0);
  entry = (void*)(pages + page - sizeof(direct));
  memcpy(entry, direct, sizeof(direct)); assert(nm_find_file_cred(entry) == 144);
  gcc[3] = 0x54000109U; entry = (void*)(pages + page - sizeof(gcc));
  memcpy(entry, gcc, sizeof(gcc)); assert(nm_find_file_cred(entry) == 144);
  bti[12] = 0xb4000056U; entry = (void*)(pages + page - sizeof(bti));
  memcpy(entry, bti, sizeof(bti)); assert(nm_find_file_cred(entry) == 144);
  assert(!munmap(pages, page * 2));
  puts("file cred entry: target, clobber, width, branch, displacement, legacy and guard pages passed");
  return 0;
}
'''
    with tempfile.TemporaryDirectory(prefix='nomount-file-cred-') as directory:
        path = Path(directory)
        (path / 'test.c').write_text(source)
        subprocess.run([compiler, '-Wall', '-Werror', '-Wno-unused-function', '-fsanitize=address,undefined',
                        str(path / 'test.c'), '-o', str(path / 'test')], check=True)
        subprocess.run([str(path / 'test')], check=True)
    if args.output:
        receipt = {
            'scope': 'Developer宿主生产函数自检；不证明独立布局、LSM/CFI或完整初始化',
            'sources': {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in
                        ('nomount/nm_offsets.c', 'kpm_utils.h', 'nomount/tools/test_dentry_entry.py')},
            'tool_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            'target_words': list(TARGET_WORDS), 'reference_offset': 144,
            'prefix_words': 22, 'legacy_failure_words': 8,
            'result': 'PASS',
        }
        with args.output.open('x') as output:
            json.dump(receipt, output, ensure_ascii=False, indent=2)
            output.write('\n')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
