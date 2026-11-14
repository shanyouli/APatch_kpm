#!/usr/bin/env python3
"""核验SUB帧属性入口与simple_getattr单B跳板；仅宿主自检，不构建或加载KPM。"""

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
# 用户miuiportspatched.img：vfs_getattr_nosec@0x3c4cd8，simple_getattr@0x3f82a4。
GETATTR = (
    0xD100C3FF, 0xA9027BFD, 0x910083FD, 0xF9400408, 0xF9401909, 0x5280FFE8,
    0xA907FC3F, 0xA906FC3F, 0xA905FC3F, 0xA904FC3F, 0xA903FC3F, 0xA902FC3F,
    0xA901FC3F, 0xA900FC3F, 0xF900003F, 0xB9000028, 0xF9401128, 0xF9404108,
    0xB4000168, 0xF0007D49, 0x91389129, 0xCB090109, 0x93C90929, 0x12002C42,
    0xF100553F, 0x12130463, 0x54000622, 0xD63F0100,
)
SIMPLE = (0xA9BE7BFD, 0xA9014FF4, 0x910003FD, 0xF9400408,
          0xAA0103F4, 0xF9401913, 0xAA1303E0, 0x943DCE95)


def main():
    """提取当前生产函数，运行正反例/保护页；返回0，编译或断言失败传播异常。

    --output可排他保存来源和真实窗口回执；只使用已有宿主Clang，不修改旧Oracle。
    PC相对BL在宿主缓冲中按同一单B关系重定位，不执行任何目标ARM64函数。
    """
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    compiler = shutil.which('clang')
    if not compiler:
        raise RuntimeError('没有已安装的宿主Clang，未执行验证')
    offsets = (ROOT / 'nomount/nm_offsets.c').read_text()
    utils = (ROOT / 'kpm_utils.h').read_text().split('// instruction\n', 1)[1].rsplit('#endif', 1)[0]
    names = (
        'nm_load', 'nm_store', 'nm_move', 'nm_load_at', 'nm_move32', 'nm_add_at', 'nm_zero64',
        'nm_store_at', 'nm_compare', 'nm_pair_store_at', 'nm_rule_entry_save', 'nm_vfs_frame_save',
        'nm_cfi_gate', 'nm_cfi_gate_stride', 'nm_movz_value', 'nm_scalar_copy_step', 'nm_scalar_copy',
        'nm_find_kstat_prefix', 'nm_check_inline_simple_getattr', 'nm_code_matches',
        'nm_check_simple_getattr', 'nm_find_getattr_layout_legacy', 'nm_find_getattr_layout_previous',
        'nm_find_sub_getattr', 'nm_find_getattr_layout',
    )
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
#define __user
typedef uint8_t u8; typedef uint16_t u16; typedef uint32_t u32; typedef uint64_t u64;
static uintptr_t core_start, core_end;
static unsigned long kallsyms_lookup_name(const char* name) {
  if (!strcmp(name, "_stext")) return core_start;
  if (!strcmp(name, "_etext")) return core_end;
  return 0;
}
static unsigned long kallsyms_lookup_name_by_suffix(const char* name) { return kallsyms_lookup_name(name); }
'''
    source += utils + (ROOT / 'nomount/nm_structs.h').read_text()
    source += offsets[:offsets.index('};') + 2] + '\nstatic volatile struct struct_offset struct_offset;\n'
    source += ''.join(function(offsets, name) for name in names)
    for name, words in (('getattr_original', GETATTR), ('simple_original', SIMPLE)):
        source += f'static const uint32_t {name}[] = {{' + ','.join(hex(word) for word in words) + '};\n'
    source += r'''
/* 把at处B/BL重定位到to，两个地址属于同一宿主映射；写指令，无返回值。
 * 测试只解释指令，不执行它；拒绝不对齐或超出imm26表示范围的位移。
 */
static void branch_to(uint32_t* at, const uint32_t* to, bool link) {
  intptr_t delta = (intptr_t)(uintptr_t)to - (intptr_t)(uintptr_t)at;
  assert(delta % 4 == 0 && delta >= -(1L << 27) && delta < (1L << 27));
  *at = (link ? 0x94000000U : 0x14000000U) | ((uint32_t)(delta / 4) & 0x3ffffffU);
}
/* 用已确认基础字段设置布局，返回值由被测生产入口取得，不种入getattr槽。 */
static void seed(void) {
  memset((void*)&struct_offset, 255, sizeof(struct_offset));
  struct_offset.inode_superblock = 40; struct_offset.inode_number = 64;
}
int main(void) {
  uint32_t arena[160] = {0};
  uint32_t* code = arena;
  uint32_t* simple = arena + 40;
  uint32_t* fill = arena + 80;
  uint32_t* jump = arena + 76;
  core_start = (uintptr_t)arena; core_end = (uintptr_t)(arena + 160);
  memcpy(code, getattr_original, sizeof(getattr_original));
  memcpy(simple, simple_original, sizeof(simple_original));
  fill[0] = 0xd65f03c0U; branch_to(jump, fill, false); branch_to(simple + 7, jump, true);
  seed();
  assert(nm_check_simple_getattr(simple, (uintptr_t)fill, true) == 0);
  assert(nm_find_sub_getattr(code, simple, (uintptr_t)fill) == 128);
  assert(nm_find_getattr_layout(code, simple, (uintptr_t)fill) == 0);
  assert(struct_offset.iop_getattr == 128 && struct_offset.getattr_callback_args == 4
         && struct_offset.getattr_function_args == 4 && struct_offset.fillattr_abi == 2
         && struct_offset.getattr_context_kind == 0);
  // 每一条都参与真实形态核验；BL/原子写回不是无害序言。
  const uint32_t replacements[] = {0xd503201fU, 0x94000000U, 0xc8097c83U};
  for (unsigned r = 0; r < sizeof(replacements) / sizeof(replacements[0]); r++) {
    for (unsigned i = 0; i < 28; i++) {
      uint32_t saved = code[i]; code[i] = replacements[r];
      assert(nm_find_sub_getattr(code, simple, (uintptr_t)fill) < 0);
      seed(); struct struct_offset before = struct_offset;
      assert(nm_find_getattr_layout(code, simple, (uintptr_t)fill) < 0);
      assert(!memcmp(&before, (const void*)&struct_offset, sizeof(before)));
      code[i] = saved;
    }
  }
  const struct { unsigned index; uint32_t word; } bad[] = {
    {0, 0x5100c3ffU}, {0, 0xd100c3e0U}, {1, 0xa90203fdU}, {2, 0x110083fdU},
    {3, 0xf9400428U}, {3, 0xb9400408U}, {4, 0xf9401929U}, {4, 0xb9401909U},
    {5, 0x5280ffd0U}, {6, 0xa907fc5fU}, {6, 0xa907fc3eU},
    {14, 0xf900005fU}, {15, 0xf9000028U}, {16, 0xf9401108U}, {16, 0xf9401129U},
    {17, 0xb9404108U}, {17, 0xf9404128U}, {18, 0x34000168U}, {18, 0xb4000128U},
    {18, 0xb4ffffe8U}, {19, 0xf0007d48U}, {20, 0x91389109U}, {21, 0xcb090129U},
    {22, 0x93c90829U}, {23, 0x92402c42U}, {23, 0x12002c62U},
    {24, 0x7100553fU}, {25, 0x12130443U}, {26, 0x54000623U}, {26, 0x54000022U},
    {27, 0xd63f0120U},
  };
  for (unsigned i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
    unsigned at = bad[i].index; uint32_t saved = code[at]; code[at] = bad[i].word;
    assert(nm_find_sub_getattr(code, simple, (uintptr_t)fill) < 0); code[at] = saved;
  }
  // 回调位置仍来自LDR，基础inode→i_op链必须同步核对，不固定128/32。
  const unsigned fields[] = {128, 144, 200, 32760};
  for (unsigned i = 0; i < sizeof(fields) / sizeof(fields[0]); i++) {
    code[17] = 0xf9400108U | ((fields[i] / 8) << 10);
    assert(nm_find_sub_getattr(code, simple, (uintptr_t)fill) == (int)fields[i]);
  }
  code[17] = 0xf9400108U; assert(nm_find_sub_getattr(code, simple, (uintptr_t)fill) == -EINVAL);
  memcpy(code, getattr_original, sizeof(getattr_original));
  struct_offset.inode_superblock = 48;
  assert(nm_find_sub_getattr(code, simple, (uintptr_t)fill) < 0);
  code[16] = 0xf9401528U; assert(nm_find_sub_getattr(code, simple, (uintptr_t)fill) == 128);
  seed(); memcpy(code, getattr_original, sizeof(getattr_original));
  code[22] = (code[22] & ~(63U << 10)) | (3U << 10);
  assert(nm_find_sub_getattr(code, simple, (uintptr_t)fill) == 128);
  memcpy(code, getattr_original, sizeof(getattr_original));
  memmove(code + 1, code, sizeof(getattr_original)); code[0] = 0xd503233fU;
  assert(nm_find_getattr_layout(code, simple, (uintptr_t)fill) == 0);
  memcpy(code, getattr_original, sizeof(getattr_original));
  // simple_getattr的全部八条都核对；CALL本身不能换成未解析的间接调用。
  for (unsigned i = 0; i < 8; i++) {
    uint32_t saved = simple[i]; simple[i] = 0xd503201fU;
    assert(nm_check_simple_getattr(simple, (uintptr_t)fill, true) < 0); simple[i] = saved;
  }
  jump[0] = 0xd503245fU; branch_to(jump + 1, fill, false);
  assert(nm_check_simple_getattr(simple, (uintptr_t)fill, true) == 0);
  branch_to(jump, jump + 1, false); branch_to(jump + 1, fill, false);
  assert(nm_check_simple_getattr(simple, (uintptr_t)fill, true) < 0); // 两跳拒绝。
  jump[0] = 0xd61f0100U; assert(nm_check_simple_getattr(simple, (uintptr_t)fill, true) < 0);
  branch_to(jump, fill, false); core_end = (uintptr_t)jump;
  assert(nm_check_simple_getattr(simple, (uintptr_t)fill, true) < 0);
  core_end = (uintptr_t)(arena + 160); core_start = 0;
  assert(nm_check_simple_getattr(simple, (uintptr_t)fill, true) < 0);
  branch_to(simple + 7, fill, true);
  assert(nm_check_simple_getattr(simple, (uintptr_t)fill, true) == 0); // 旧直接BL无新增边界前提。
  core_start = (uintptr_t)arena;
  // 旧path形态仍执行其原29条判据；新的SUB分支不替换旧接受条件。
  uint32_t legacy[29]; memcpy(legacy, getattr_original + 3, 16 * 4);
  legacy[15] = 0xb40001c8U;
  legacy[16] = 0xa9bd7bfdU; legacy[17] = 0xd100c3ffU;
  legacy[18] = 0xa9014ff4U; legacy[19] = 0x910083fdU;
  legacy[20] = getattr_original[19]; legacy[21] = getattr_original[20];
  legacy[22] = getattr_original[21]; legacy[23] = getattr_original[22];
  legacy[24] = getattr_original[24]; legacy[25] = getattr_original[26];
  legacy[26] = getattr_original[23]; legacy[27] = getattr_original[25]; legacy[28] = getattr_original[27];
  seed(); assert(nm_find_getattr_layout(legacy, simple, (uintptr_t)fill) == 0);
  // 两组独立保护页分别贴紧28条入口和8条simple入口；BL重定位仍在同一映射内。
  long page = sysconf(_SC_PAGESIZE); assert(page > 512);
  unsigned char* pages = mmap(NULL, page * 4, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
  assert(pages != MAP_FAILED && !mprotect(pages + page, page, PROT_NONE)
         && !mprotect(pages + page * 3, page, PROT_NONE));
  uint32_t* entry = (void*)(pages + page - sizeof(getattr_original));
  uint32_t* guarded_simple = (void*)(pages + page * 3 - sizeof(simple_original));
  uint32_t* guarded_fill = (void*)(pages + page * 2);
  uint32_t* guarded_jump = guarded_fill + 4;
  guarded_fill[0] = 0xd65f03c0U; branch_to(guarded_jump, guarded_fill, false);
  memcpy(entry, getattr_original, sizeof(getattr_original));
  memcpy(guarded_simple, simple_original, sizeof(simple_original));
  branch_to(guarded_simple + 7, guarded_jump, true);
  core_start = (uintptr_t)pages; core_end = (uintptr_t)(pages + page * 4);
  seed(); assert(nm_find_getattr_layout(entry, guarded_simple, (uintptr_t)guarded_fill) == 0);
  for (unsigned i = 0; i < 28; i++) {
    uint32_t saved = entry[i]; entry[i] = 0xd503201fU;
    assert(nm_find_getattr_layout(entry, guarded_simple, (uintptr_t)guarded_fill) < 0); entry[i] = saved;
  }
  entry = (void*)(pages + page - sizeof(getattr_original) - 4);
  entry[0] = 0xd503233fU; memcpy(entry + 1, getattr_original, sizeof(getattr_original));
  assert(nm_find_getattr_layout(entry, guarded_simple, (uintptr_t)guarded_fill) == 0);
  for (unsigned i = 0; i < 8; i++) {
    uint32_t saved = guarded_simple[i]; guarded_simple[i] = 0xd503201fU;
    assert(nm_check_simple_getattr(guarded_simple, (uintptr_t)guarded_fill, true) < 0);
    guarded_simple[i] = saved;
  }
  assert(!munmap(pages, page * 4));
  puts("getattr entry: SUB frame, masks, CFI single branch, fields, legacy and guard pages passed");
  return 0;
}
'''
    with tempfile.TemporaryDirectory(prefix='nomount-getattr-entry-') as directory:
        path = Path(directory)
        (path / 'test.c').write_text(source)
        subprocess.run([compiler, '-Wall', '-Werror', '-Wno-unused-function', '-fsanitize=address,undefined',
                        str(path / 'test.c'), '-o', str(path / 'test')], check=True)
        subprocess.run([str(path / 'test')], check=True)
    if args.output:
        receipt = {
            'scope': 'Developer宿主生产函数自检；非独立审计、真实CFI或完整初始化结论',
            'sources': {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in
                        ('nomount/nm_offsets.c', 'nomount/nm_structs.h', 'kpm_utils.h', 'nomount/tools/test_dentry_entry.py')},
            'tool_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            'getattr_words': list(GETATTR), 'simple_words': list(SIMPLE),
            'window_words': 28, 'simple_window_words': 8, 'reference_getattr': 128, 'result': 'PASS',
        }
        with args.output.open('x') as output:
            json.dump(receipt, output, ensure_ascii=False, indent=2)
            output.write('\n')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
