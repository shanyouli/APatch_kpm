#!/usr/bin/env python3
"""核验目标super/目录操作入口；仅宿主生产函数自检，不加载KPM或放宽尾部契约。"""
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
# 来自miuiportspatched.img；窗口分别止于put_super调用、iterate守卫、prune调用和actor返回。
WINDOWS = {
    'super': (0xA9BD7BFD, 0xF9000BF5, 0xA9024FF4, 0x910003FD, 0xF9403408, 0xAA0003F3,
              0xB4000668, 0xF9401A75, 0x9101C260, 0x943EA0EC, 0x35000AA0, 0xF9403660,
              0xF900367F, 0x94008006, 0xF9406A68, 0xF100091F, 0x54000922, 0xAA1303E0,
              0x943ECD43, 0xF9402A68, 0xAA1303E0, 0x9261F908, 0xF9002A68, 0x940175B1,
              0xF0012808, 0xB9472108, 0x340000E8, 0xF0010960, 0x91320000, 0x97FA59A0,
              0xF0012808, 0xF9439500, 0x97F80FEC, 0xAA1303E0, 0x940094BF, 0xF9427A60,
              0xB4000060, 0x97F81A37, 0xF9027A7F, 0xF9401AB4, 0xB4000134, 0xB0007D68,
              0x9103D108, 0xCB080288, 0x93C80908, 0xF100A51F, 0x54000702, 0xAA1303E0, 0xD63F0280),
    'iterate': (0xA9BB7BFD, 0xF9000BF9, 0xA9025FF8, 0xA90357F6, 0xA9044FF4, 0x910003FD,
                0xA9422018, 0xAA0003F3, 0xAA0103F4, 0xF9401D09, 0xB4000229),
    'prune': (0xA9BC7BFD, 0xF9000BF7, 0xA90257F6, 0xA9034FF4, 0x910003FD, 0xF9400C08,
              0x91016015, 0xAA0003F3, 0xAA1E03F4, 0xEB00011F, 0xAA1503E0, 0x9A8803F7,
              0x9409CEC8, 0xB9400268, 0x36200188, 0xF9403268, 0xF9401D16, 0xD0007CA8,
              0x912E5108, 0xCB0802C8, 0x93C80908, 0xF100411F, 0x54001162, 0xAA1303E0, 0xD63F02C0),
    'actor': (0xA9BC7BFD, 0xF9000BF7, 0xA90257F6, 0xA9034FF4, 0x910003FD, 0xF9400428,
              0xAA0103F3, 0xAA0003F4, 0xF100051F, 0x540002C0, 0xB5000628, 0xF9400275,
              0xB0007BE8, 0x911F9108, 0xCB0802A8, 0x93C80908, 0xF100311F, 0x54000702,
              0xAA1F03E3, 0xF9400E88, 0xD000A721, 0x911E0021, 0x52800022, 0xF9401908,
              0x52800085, 0xAA1303E0, 0xF9402104, 0xD63F02A0, 0x350003E0),
}


def main():
    """提取当前生产函数并运行正反例、旧路径和保护页，成功返回0，失败传播异常。

    --output排他保存源哈希及窗口；真实BL按同一具名目标关系重定位到宿主缓冲，
    不执行目标指令，不修改已有Oracle，不把未知联合尾部当作完整sizeof。
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
        'nm_cfi_gate', 'nm_cfi_gate_stride', 'nm_movz_value', 'nm_code_matches',
        'nm_find_super_lifecycle_legacy', 'nm_super_named_call', 'nm_find_shutdown_workqueue', 'nm_find_super_lifecycle',
        'nm_check_directory_iteration_legacy', 'nm_check_directory_iteration',
        'nm_find_dentry_lifecycle_legacy', 'nm_dentry_prune_slot', 'nm_find_saved_dentry_prune', 'nm_find_dentry_lifecycle',
        'nm_find_directory_actor_legacy', 'nm_find_five_frame_actor', 'nm_find_directory_actor',
        'nm_tail_extent', 'nm_set_operation_extents',
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
static const char* missing;
static uint32_t* targets[9];
static const char* call_names[] = {"down_read_trylock", "do_one_tree", "sync_filesystem",
  "fsnotify_unmount_inodes", "_rcu_barrier", "flush_workqueue", "evict_inodes", "destroy_workqueue", "lockref_mark_dead"};
static unsigned long kallsyms_lookup_name(const char* name) {
  if (!strcmp(name, "_stext")) return core_start;
  if (!strcmp(name, "_etext")) return core_end;
  return 0;
}
static unsigned long kallsyms_lookup_name_by_suffix(const char* name) {
  if (missing && !strcmp(name, missing)) return 0;
  for (unsigned i = 0; i < 9; i++) if (!strcmp(name, call_names[i])) return (uintptr_t)targets[i];
  return kallsyms_lookup_name(name);
}
'''
    source += utils + (ROOT / 'nomount/nm_structs.h').read_text()
    source += offsets[:offsets.index('};') + 2] + '\nstatic volatile struct struct_offset struct_offset;\n'
    source += ''.join(function(offsets, name) for name in names)
    for name, words in WINDOWS.items():
        source += f'static const uint32_t {name}_original[] = {{' + ','.join(hex(word) for word in words) + '};\n'
    source += r'''
/* at处BL重定位到同一宿主映射内的to，不执行指令；越界/不对齐时断言失败。 */
static void branch_to(uint32_t* at, const uint32_t* to, bool link) {
  intptr_t delta = (intptr_t)(uintptr_t)to - (intptr_t)(uintptr_t)at;
  assert(delta % 4 == 0 && delta >= -(1L << 27) && delta < (1L << 27));
  *at = (link ? 0x94000000U : 0x14000000U) | ((uint32_t)(delta / 4) & 0x3ffffffU);
}
/* 为kind所选窗口重定位已知BL；其余机器码不变，无返回值。 */
static void relocate(unsigned kind, uint32_t* code, unsigned prefix) {
  const unsigned calls[] = {9, 13, 18, 23, 29, 32, 34, 37};
  if (!kind) for (unsigned i = 0; i < 8; i++) branch_to(code + prefix + calls[i], targets[i] + 1, true);
  if (kind == 2) branch_to(code + prefix + 12, targets[8] + 1, true);
}
/* 设置已确认的基础/前置字段，不种入被测回调槽；无返回值。 */
static void seed(void) {
  memset((void*)&struct_offset, 255, sizeof(struct_offset));
  struct_offset.file_inode_ops = 32; struct_offset.file_ops_size = 240;
  struct_offset.inode_number = 64; struct_offset.dentry_ops = 96; struct_offset.dentry_lock = 88;
}
/* 直接执行kind对应的生产识别器，返回原始状态，不模拟内核调用或发布对象。 */
static int run_entry(unsigned kind, const uint32_t* code) {
  switch (kind) {
    case 0: return nm_find_super_lifecycle(code);
    case 1: return nm_check_directory_iteration(code, 56);
    case 2: return nm_find_dentry_lifecycle(code, (uintptr_t)targets[8], core_start, core_end);
    default: return nm_find_directory_actor(code);
  }
}
int main(void) {
  uint32_t arena[4096] = {0}; core_start = (uintptr_t)arena; core_end = (uintptr_t)(arena + 4096);
  for (unsigned i = 0; i < 9; i++) {
    targets[i] = arena + 2048 + i * 8; targets[i][0] = 0xd65f03c0U;
    branch_to(targets[i] + 1, targets[i], false);
  }
  const uint32_t* originals[] = {super_original, iterate_original, prune_original, actor_original};
  const unsigned counts[] = {49, 11, 25, 29};
  const uint32_t replacements[] = {0xd503201fU, 0x94000000U, 0xc8147c83U};
  for (unsigned kind = 0; kind < 4; kind++) {
    uint32_t* code = arena + kind * 256;
    memcpy(code, originals[kind], counts[kind] * 4); relocate(kind, code, 0); seed();
    assert(run_entry(kind, code) == 0);
    if (!kind) assert(struct_offset.sop_drop_inode == 32 && struct_offset.sop_evict_inode == 40);
    if (kind == 1) assert(struct_offset.fop_iterate == 48 && struct_offset.fop_iterate_shared == 56);
    if (kind == 2) assert(struct_offset.dop_init == 40 && struct_offset.dop_release == 48);
    for (unsigned r = 0; r < 3; r++) for (unsigned at = 0; at < counts[kind]; at++) {
      uint32_t saved = code[at]; code[at] = replacements[r]; seed();
      assert(run_entry(kind, code) < 0); code[at] = saved;
    }
    // W/X截断、错误来源、写回和跳进/跳过调用分别拒绝。
    const unsigned indexes[4][6] = {{7, 19, 33, 39, 40, 48}, {6, 6, 7, 9, 10, 9},
                                   {7, 8, 13, 15, 16, 24}, {5, 7, 19, 23, 26, 28}};
    const uint32_t bad[4][6] = {{0xf9401a74U, 0xb9402a68U, 0xaa1403e0U, 0xb9401ab4U, 0xb4000034U, 0xd63f0260U},
                               {0xa9422418U, 0xa9c22018U, 0x2a0003f3U, 0xf9401d29U, 0x34000229U, 0xb9401d09U},
                               {0x2a0003f3U, 0xaa0103f4U, 0xf9400268U, 0xf9403269U, 0xb9401d16U, 0xd63f02a0U},
                               {0xb9400428U, 0x2a0003f4U, 0xf9400e68U, 0xf9401928U, 0xb9402104U, 0xb50003e0U}};
    for (unsigned i = 0; i < 6; i++) {
      unsigned at = indexes[kind][i]; uint32_t saved = code[at]; code[at] = bad[kind][i];
      seed(); assert(run_entry(kind, code) < 0); code[at] = saved;
    }
    memmove(code + 1, code, counts[kind] * 4); code[0] = 0xd503233fU;
    relocate(kind, code, 1); seed(); assert(run_entry(kind, code) == 0);
  }
  // 具名调用缺失或指向其它合法核心函数仍拒绝，不能仅凭BL就跨调用保持来源。
  uint32_t* super = arena; memcpy(super, super_original, sizeof(super_original)); relocate(0, super, 0);
  for (unsigned i = 0; i < 8; i++) {
    missing = call_names[i]; seed(); assert(nm_find_super_lifecycle(super) < 0);
  }
  missing = NULL; branch_to(super + 9, targets[1], true); seed(); assert(nm_find_super_lifecycle(super) < 0);
  relocate(0, super, 0); seed(); super[39] = 0xf94026b4U;
  assert(nm_find_super_lifecycle(super) == 0 && struct_offset.sop_drop_inode == 56 && struct_offset.sop_evict_inode == 64);
  // BTI C+单B可接受，两跳拒绝。
  memcpy(super, super_original, sizeof(super_original));
  targets[0][1] = 0xd503245fU; branch_to(targets[0] + 2, targets[0], false);
  relocate(0, super, 0); seed(); assert(nm_find_super_lifecycle(super) == 0);
  branch_to(targets[0] + 1, targets[0] + 2, false); seed(); assert(nm_find_super_lifecycle(super) < 0);
  branch_to(targets[0] + 1, targets[0], false);
  // 旧25条直接回调路径保留；新分支不延长其成功读取范围。
  uint32_t legacy[25]; for (unsigned i = 0; i < 25; i++) legacy[i] = 0xaa1303e0U;
  legacy[0] = 0xa9bd7bfdU; legacy[1] = 0xf9000bf5U; legacy[2] = 0xa9024ff4U;
  legacy[3] = 0xaa0003f3U; legacy[4] = 0xf9403401U; legacy[5] = 0xf9401814U;
  legacy[6] = 0xb4000281U; legacy[21] = 0xf9401a81U; legacy[22] = 0xb4000061U;
  legacy[23] = 0xaa1303e0U; legacy[24] = 0xd63f0020U;
  seed(); assert(nm_find_super_lifecycle(legacy) == 0);
  // 原有完整尾部契约仍可接受；目标尚未确认的联合几何保持拒绝，尺寸不被猜填。
  seed(); struct_offset.iop_getattr = 128; struct_offset.sop_drop_inode = 32; struct_offset.sop_evict_inode = 40;
  struct_offset.dop_init = 40; struct_offset.dop_release = 48;
  assert(nm_set_operation_extents(176, 224, 104) == 0);
  seed(); struct_offset.iop_getattr = 128; struct_offset.sop_drop_inode = 32; struct_offset.sop_evict_inode = 40;
  struct_offset.dop_init = 40; struct_offset.dop_release = 48;
  assert(nm_set_operation_extents(176, 216, 104) < 0);
  assert(nm_set_operation_extents(176, 216, 112) < 0);
  assert(struct_offset.inode_ops_size == -1 && struct_offset.super_ops_size == -1 && struct_offset.dentry_ops_size == -1);
  // 四个窗口各贴保护页；所有CFI样本放在同一可读映射内，禁止读到下一页。
  long page = sysconf(_SC_PAGESIZE); assert(page > 1024);
  unsigned char* pages = mmap(NULL, page * 8, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
  assert(pages != MAP_FAILED);
  for (unsigned i = 1; i < 8; i += 2) assert(!mprotect(pages + page * i, page, PROT_NONE));
  core_start = (uintptr_t)pages; core_end = (uintptr_t)(pages + page * 8);
  for (unsigned i = 0; i < 9; i++) {
    targets[i] = (void*)(pages + page * 6 + i * 32); targets[i][0] = 0xd65f03c0U;
    branch_to(targets[i] + 1, targets[i], false);
  }
  for (unsigned kind = 0; kind < 4; kind++) {
    uint32_t* code = (void*)(pages + page * (kind * 2 + 1) - counts[kind] * 4);
    memcpy(code, originals[kind], counts[kind] * 4); relocate(kind, code, 0); seed();
    assert(run_entry(kind, code) == 0);
    for (unsigned at = 0; at < counts[kind]; at++) {
      uint32_t saved = code[at]; code[at] = 0xd503201fU; seed(); assert(run_entry(kind, code) < 0); code[at] = saved;
    }
    code--; code[0] = 0xd503233fU; memcpy(code + 1, originals[kind], counts[kind] * 4);
    relocate(kind, code, 1); seed(); assert(run_entry(kind, code) == 0);
  }
  uint32_t* old = (void*)(pages + page - sizeof(legacy)); memcpy(old, legacy, sizeof(legacy));
  seed(); assert(nm_find_super_lifecycle(old) == 0);
  assert(!munmap(pages, page * 8));
  puts("operation entries: target windows, calls, clobbers, legacy, guard pages and unknown-tail rejection passed");
  return 0;
}
'''
    with tempfile.TemporaryDirectory(prefix='nomount-operation-entries-') as directory:
        path = Path(directory)
        (path / 'test.c').write_text(source)
        subprocess.run([compiler, '-Wall', '-Werror', '-Wno-unused-function', '-fsanitize=address,undefined',
                        str(path / 'test.c'), '-o', str(path / 'test')], check=True)
        subprocess.run([str(path / 'test')], check=True)
    if args.output:
        receipt = {
            'scope': 'Developer宿主生产函数自检；非独立审计、原生CFI/调用或完整初始化结论',
            'sources': {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in
                        ('nomount/nm_offsets.c', 'nomount/nm_structs.h', 'kpm_utils.h', 'nomount/tools/test_dentry_entry.py')},
            'tool_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            'windows': {name: {'words': list(words), 'count': len(words)} for name, words in WINDOWS.items()},
            'result': 'PASS',
        }
        with args.output.open('x') as output:
            json.dump(receipt, output, ensure_ascii=False, indent=2)
            output.write('\n')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
