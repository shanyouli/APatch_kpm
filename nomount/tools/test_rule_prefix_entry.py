#!/usr/bin/env python3
"""核验目标规则入口的生产代码与拒绝边界；不构建或加载KPM。"""

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
# miuiportspatched.img 的真实短入口，位置与原始机器码分别保留在本地证据。
OPEN = (0xA9BC7BFD, 0xF9000BF7, 0xA90257F6, 0xA9034FF4, 0x910003FD, 0xF9400008, 0xB4000268)
VFS = (0xD10103FF, 0xA9017BFD, 0xF90013F5, 0xA9034FF4, 0x910043FD,
       0xAA0003F5, 0xF9400400, 0xAA0203F3, 0xAA0103F4, 0x39400C08,
       0x371001E8, 0xB13FFC1F, 0x54000102, 0xA94022A9, 0xAA1F03E2,
       0xAA1303E3, 0xA9012289, 0xF9401801, 0xAA1403E0)
HASH = (0xAA1F03E8, 0x34000262, 0x531D7049, 0xF940002A, 0x71002042, 0x54000163)


def main():
    """用已安装Clang运行生产函数正反例；成功返回0，任何失败传播异常。

    可选--output排他保存来源哈希及真实入口；输出已存在时拒绝覆盖。
    所有二进制仅为临时宿主测试，不下载依赖、不操作设备。
    """
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    compiler = shutil.which('clang')
    if not compiler:
        raise RuntimeError('没有已安装的宿主Clang，未执行验证')
    offsets = (ROOT / 'nomount/nm_offsets.c').read_text()
    utils = (ROOT / 'kpm_utils.h').read_text().split('// instruction\n', 1)[1].rsplit('#endif', 1)[0]
    names = ('nm_load', 'nm_store', 'nm_move', 'nm_load_at', 'nm_move32', 'nm_add_at',
             'nm_zero64', 'nm_store_at', 'nm_pair_store_at', 'nm_find_name_hash_arguments',
             'nm_rule_entry_save', 'nm_check_rule_sub_frame', 'nm_check_rule_prefixes')
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
typedef uint8_t u8; typedef uint16_t u16; typedef uint32_t u32; typedef uint64_t u64;
'''
    source += utils + (ROOT / 'nomount/nm_structs.h').read_text()
    # 使用真实配置表定义；仅为被测函数设置已由基础阶段确认的file片段起点。
    source += offsets[:offsets.index('};') + 2] + '\nstatic volatile struct struct_offset struct_offset;\n'
    source += ''.join(function(offsets, name) for name in names)
    for name, words in (('open_original', OPEN), ('vfs_original', VFS), ('hash_original', HASH)):
        source += f'static const uint32_t {name}[] = {{' + ','.join(hex(word) for word in words) + '};\n'
    source += r'''
int main(void) {
  uint32_t open[20], vfs[20], hash[8];
  memset(open, 0, sizeof(open)); memset(vfs, 0, sizeof(vfs)); memset(hash, 0, sizeof(hash));
  memcpy(open, open_original, sizeof(open_original));
  memcpy(vfs, vfs_original, sizeof(vfs_original));
  memcpy(hash, hash_original, sizeof(hash_original));
  struct_offset.file_inode_ops = 32;
  assert(nm_find_name_hash_arguments(hash) == 3);
  assert(nm_check_rule_sub_frame(vfs) == 0);
  assert(nm_check_rule_prefixes(open, vfs) == 0);
  // 原始入口逐条NOP；每次独立还原，不改冻结Oracle。
  for (unsigned i = 0; i < 7; i++) {
    uint32_t saved = open[i]; open[i] = 0xd503201fU;
    assert(nm_check_rule_prefixes(open, vfs) < 0); open[i] = saved;
  }
  for (unsigned i = 0; i < 19; i++) {
    uint32_t saved = vfs[i]; vfs[i] = 0xd503201fU;
    assert(nm_check_rule_sub_frame(vfs) < 0);
    assert(nm_check_rule_prefixes(open, vfs) < 0); vfs[i] = saved;
  }
  const struct { unsigned index; uint32_t word; } bad_vfs[] = {
    {0, 0xd10103e0U}, {1, 0xa90103fdU}, {2, 0xf90017f5U}, {4, 0x110043fdU},
    {5, 0xaa0103f5U}, {6, 0xf9400420U}, {6, 0xb9400400U},
    {7, 0xaa0103f3U}, {8, 0xaa0203f4U}, {9, 0x39400c28U}, {9, 0x79400c08U},
    {10, 0x371001e9U}, {10, 0x371000a8U}, {11, 0xb13ffc20U},
    {12, 0x54000103U}, {12, 0x54000082U},
    {13, 0xa94022c9U}, {13, 0xa94026a9U}, {13, 0xa9c022a9U},
    {14, 0x2a1f03e2U}, {15, 0xaa1203e3U},
    {16, 0xa90122a9U}, {16, 0xa9012689U}, {17, 0xf9401821U}, {18, 0xaa1503e0U}
  };
  for (unsigned i = 0; i < sizeof(bad_vfs)/sizeof(bad_vfs[0]); i++) {
    unsigned at = bad_vfs[i].index; uint32_t saved = vfs[at]; vfs[at] = bad_vfs[i].word;
    assert(nm_check_rule_prefixes(open, vfs) < 0); vfs[at] = saved;
  }
  const uint32_t bad_mount[] = {0xf9400028U, 0xb9400008U, 0xf9400000U};
  for (unsigned i = 0; i < 3; i++) {
    open[5] = bad_mount[i]; assert(nm_check_rule_prefixes(open, vfs) < 0);
  }
  memcpy(open, open_original, sizeof(open_original));
  open[6] = 0x34000268U; assert(nm_check_rule_prefixes(open, vfs) < 0);
  memcpy(open, open_original, sizeof(open_original));
  // 复制位置仍绑定真实file片段，不能直接返回成功或写死16。
  struct_offset.file_inode_ops = 40;
  assert(nm_check_rule_prefixes(open, vfs) < 0);
  vfs[16] = 0xa901a289U;
  assert(nm_check_rule_prefixes(open, vfs) == 0);
  struct_offset.file_inode_ops = 32; memcpy(vfs, vfs_original, sizeof(vfs_original));
  // PAC仅增加已支持的一条提示，来源与所有检查不变。
  memmove(open + 1, open, sizeof(open_original)); open[0] = 0xd503233fU;
  memmove(vfs + 1, vfs, sizeof(vfs_original)); vfs[0] = 0xd503233fU;
  assert(nm_check_rule_prefixes(open, vfs) == 0);
  memcpy(open, open_original, sizeof(open_original)); memcpy(vfs, vfs_original, sizeof(vfs_original));
  // 原四条帧的Clang路径保持原谓词；不修改现存用例与断言。
  uint32_t legacy[18];
  legacy[0] = 0xa9bd7bfdU; legacy[1] = 0xf9000bf5U; legacy[2] = 0xa9024ff4U; legacy[3] = 0x910003fdU;
  memcpy(legacy + 4, vfs_original + 5, 14*4);
  assert(nm_check_rule_prefixes(open, legacy) == 0);
  // 保护页：新入口open7条/vfs19条，旧入口和hash保留各自短范围。
  long page = sysconf(_SC_PAGESIZE); assert(page > 256);
  unsigned char* a = mmap(NULL, page*2, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANON, -1, 0);
  unsigned char* b = mmap(NULL, page*2, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANON, -1, 0);
  assert(a != MAP_FAILED && b != MAP_FAILED);
  assert(!mprotect(a + page, page, PROT_NONE) && !mprotect(b + page, page, PROT_NONE));
  uint32_t* x = (void*)(a + page - sizeof(open_original));
  uint32_t* y = (void*)(b + page - sizeof(vfs_original));
  memcpy(x, open_original, sizeof(open_original)); memcpy(y, vfs_original, sizeof(vfs_original));
  assert(nm_check_rule_prefixes(x, y) == 0);
  y[18] = 0xd503201fU; assert(nm_check_rule_prefixes(x, y) < 0);
  // PAC前缀也紧贴保护页，额外一条不扩大字段扫描窗口。
  x = (void*)(a + page - sizeof(open_original) - 4);
  y = (void*)(b + page - sizeof(vfs_original) - 4);
  x[0] = 0xd503233fU; memcpy(x + 1, open_original, sizeof(open_original));
  y[0] = 0xd503233fU; memcpy(y + 1, vfs_original, sizeof(vfs_original));
  assert(nm_check_rule_prefixes(x, y) == 0);
  y = (void*)(b + page - sizeof(vfs_original)); memcpy(y, vfs_original, sizeof(vfs_original));
  x = (void*)(a + page - 5*4); x[0] = 0xf9400008U;
  assert(nm_check_rule_prefixes(x, y) == 0);
  y = (void*)(b + page - sizeof(legacy)); memcpy(y, legacy, sizeof(legacy));
  assert(nm_check_rule_prefixes(x, y) == 0);
  x = (void*)(a + page - sizeof(hash_original)); memcpy(x, hash_original, sizeof(hash_original));
  assert(nm_find_name_hash_arguments(x) == 3);
  assert(!munmap(a, page*2) && !munmap(b, page*2));
  puts("rule prefix entry checks passed");
  return 0;
}
'''
    with tempfile.TemporaryDirectory(prefix='nomount-rule-entry-') as directory:
        out = Path(directory)
        (out / 'test.c').write_text(source)
        subprocess.run([compiler, '-Wall', '-Werror', '-Wno-unused-function', '-fsanitize=address,undefined',
                        str(out / 'test.c'), '-o', str(out / 'test')], check=True)
        subprocess.run([str(out / 'test')], check=True)
    if args.output:
        receipt = {'scope': 'Developer生产规则入口宿主核验；不证明真机加载、CFI或并发',
                   'production_sha256': hashlib.sha256(offsets.encode()).hexdigest(),
                   'utils_sha256': hashlib.sha256((ROOT / 'kpm_utils.h').read_bytes()).hexdigest(),
                   'tool_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                   'open_words': list(OPEN), 'vfs_words': list(VFS), 'hash_words': list(HASH),
                   'windows': {'dentry_open': 7, 'vfs_open': 19, 'full_name_hash': 6}}
        with args.output.open('x') as output:
            json.dump(receipt, output, ensure_ascii=False, indent=2)
            output.write('\n')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
