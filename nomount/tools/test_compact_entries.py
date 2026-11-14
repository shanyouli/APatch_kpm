#!/usr/bin/env python3
"""核验compact声明族及剩余初始化短入口；宿主自检，不执行内核代码或修改旧Oracle。"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

sys.dont_write_bytecode = True
from test_dentry_entry import function

ROOT = Path(__file__).resolve().parents[2]
# miuiportspatched.img的真实窗口；BL/ADRP按相同对象关系重定位到宿主缓冲。
WORDS = {
    'align': 'f9400008 93407c29 8b091908 f9401500 d65f03c0',
    'init': 'd10103ff a9017bfd a90257f6 a9034ff4 910043fd f9001420 39405008 52800029 b9000c3f b000c134 b9009028 b000b6c8 91340108 f900b03f b9016829 f9001028 b000b6c8 91370108 f900bc28',
    'clear': 'aa0003e8 aa0003e9 5280040a a90a7c1f a9087c1f a9077c1f a9067c1f a9057c1f a9047c1f a902fc1f a901fc1f a900fc1f 72a0230a f8090d1f f8038d3f f9004c1f f900001f b900080a f900081f b900181f f900181f b900481f f9000129 f9002009 a9057c1f b9004c1f f9000108 f9004c08 b900881f a9027c1f d65f03c0',
    'prep': 'a9be7bfd a9014ff4 910003fd f9401813 528fffc9 d1000668 eb09011f 54000248 f9401408 aa0003f4 b40001e8',
    'reg': 'a9bc7bfd f9000bf7 a90257f6 a9034ff4 910003fd aa0003f3 d000fb40 9112c000 94366078 d000fb56 911382d6 f94002d4 eb16029f 54000140 f9400275 aa1403f7 f85882e0 aa1503e1 97e94f97',
    'key': 'd10283ff a9067bfd f9003bf7 a90857f6 a9094ff4 910183fd f000f6c8 f947fd08 aa0003f3 92f0000a aa0403f4 f81f83a8 a9017fff a9027fff a904ffff a90307ff f90023e2 f8490e68 aa0003f5 aa0303f6 f9400509 a904abe9 f9400d17',
    'unreg': 'a9bd7bfd f9000bf5 a9024ff4 910003fd aa0003f3 d000fb40 9112c000 94366034 9101e274 aa1403e0 9402bb7e 36000080 a947a269 f9000528 f9000109 d000fb40 9112c000 f9003e74 f9004274',
    'permission': 'a9bf7bfd 910003fd 2a0103e2 aa0003e1 370800a2 aa1f03e0 97ffff6b',
    'native': 'a9bf7bfd 910003fd 370800c2 97ffff83',
}


def main():
    """提取当前生产函数及依赖，执行窗口/尺寸/边界正反例，失败传播异常。

    可选--output排他保存源哈希与窗口；使用已有Clang和临时目录。
    原生函数仅以可解释指令或表关系模拟，不调用宿主外的函数地址。
    """
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    compiler = shutil.which('clang')
    if not compiler:
        raise RuntimeError('没有已安装的宿主Clang，未执行测试')
    offsets = (ROOT / 'nomount/nm_offsets.c').read_text()
    prefix = offsets.split('// int保留', 1)[0].replace('__attribute__((section(".data.re_offsets"), used))', '')
    selected = {}

    def collect(name):
        """收集具名生产定义及静态函数依赖，保持源顺序；宏/外部接口不重写。"""
        if name in selected:
            return
        try:
            body = function(offsets, name)
        except ValueError:
            return
        if offsets.index(body.rstrip()) < len(prefix):
            return
        selected[name] = body
        for dependency in re.findall(r'\b((?:nm_|calculate_)\w+)\s*\(', body):
            if dependency != name:
                collect(dependency)

    for name in ('nm_set_compact_operation_extents', 'nm_probe_sub_inode_storage', 'nm_find_mapping_clear_size',
                 'nm_scalar_copy', 'nm_check_split_permission', 'nm_find_key_registration',
                 'nm_find_key_callback_slot', 'nm_find_key_type_link', 'nm_prepare_control_layout'):
        collect(name)
    probe = offsets[offsets.index('struct nm_initial_fops_probe {'):]
    probe = probe[:probe.index('};') + 2]
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
#define ARRAY_SIZE(a) (sizeof(a)/sizeof((a)[0]))
#define nm_log_info(...) ((void)0)
#define nm_log_error(...) ((void)0)
typedef uint8_t u8; typedef uint16_t u16; typedef uint32_t u32; typedef uint64_t u64;
static unsigned char* arena;
static uint32_t *alignment, *initializer, *clearer, *prep, *reg, *key, *unreg, *permission, *native;
static uint32_t *compare, *down, *valid, *impl, *free_preparse, *instantiate, *no_open;
static uintptr_t core_start, core_end;
static uintptr_t key_table[32];
static int lookups, btf_mode;
static unsigned long kallsyms_lookup_name(const char* name) {
  lookups++;
  if (!strcmp(name,"_stext")) return core_start;
  if (!strcmp(name,"_etext")) return core_end;
  if (!strcmp(name,"list_lru_count_node")) return (uintptr_t)alignment;
  if (!strcmp(name,"user_preparse")) return (uintptr_t)prep;
  if (!strcmp(name,"register_key_type")) return (uintptr_t)reg;
  if (!strcmp(name,"key_instantiate_and_link")) return (uintptr_t)key;
  if (!strcmp(name,"unregister_key_type")) return (uintptr_t)unreg;
  if (!strcmp(name,"key_type_user")) return (uintptr_t)key_table;
  if (!strcmp(name,"strcmp")) return (uintptr_t)compare;
  if (!strcmp(name,"down_write")) return (uintptr_t)down;
  if (!strcmp(name,"__list_del_entry_valid")) return (uintptr_t)valid;
  if (!strcmp(name,"__inode_permission2")) return (uintptr_t)impl;
  if (!strcmp(name,"user_free_preparse")) return (uintptr_t)free_preparse;
  if (!strcmp(name,"generic_key_instantiate")) return (uintptr_t)instantiate;
  return 0;
}
static unsigned long kallsyms_lookup_name_by_suffix(const char* name) { return kallsyms_lookup_name(name); }
static int calculate_btf_control_layout(bool* unavailable) {
  *unavailable = btf_mode == 0;
  return btf_mode == 1 ? -EINVAL : -ENODATA;
}
'''
    source += (ROOT / 'kpm_utils.h').read_text().split('// instruction\n', 1)[1].rsplit('#endif', 1)[0]
    source += (ROOT / 'nomount/nm_structs.h').read_text() + prefix + probe + '\n'
    if 'static bool nm_owned_operation_fallback' not in prefix:
        source += 'static bool nm_owned_operation_fallback;\n'
    source += ''.join(selected[name] for name in sorted(selected, key=lambda n: offsets.index(selected[n].rstrip())))
    for name, hexes in WORDS.items():
        source += f'static const uint32_t {name}_original[] = {{' + ','.join('0x' + word + 'U' for word in hexes.split()) + '};\n'
    source += r'''
/* 在同一可读宿主映射内编码B/BL，拒绝不对齐或超范围；不执行指令。 */
static void branch_to(uint32_t* at, const uint32_t* to, bool link) {
  intptr_t delta = (intptr_t)(uintptr_t)to - (intptr_t)(uintptr_t)at;
  assert(delta % 4 == 0 && delta >= -(1L << 27) && delta < (1L << 27));
  *at = (link ? 0x94000000U : 0x14000000U) | ((uint32_t)(delta / 4) & 0x3ffffffU);
}
/* 重定位ADRP/ADD到同一映射的table，不改其它机器码。 */
static void address_to(uint32_t* at, uintptr_t table) {
  intptr_t pages = ((intptr_t)(table & ~(uintptr_t)4095) - (intptr_t)((uintptr_t)at & ~(uintptr_t)4095)) / 4096;
  assert(pages >= -(1L << 20) && pages < (1L << 20));
  uint32_t encoded = (uint32_t)pages & 0x1fffffU;
  at[0] = 0x90000008U | ((encoded & 3U) << 29) | ((encoded >> 2) << 5);
  at[1] = 0x91000108U | ((table & 4095U) << 10);
}
/* 设置已独立取得的compact前置字段，待测完整尺寸保持-1。 */
static void seed(void) {
  memset((void*)&struct_offset,255,sizeof(struct_offset));
  struct_offset.file_ops_size = 240; struct_offset.fop_io_bias = 0;
  struct_offset.fop_open = 96; struct_offset.fop_release = 112; struct_offset.fop_mmap = 88;
  struct_offset.fop_splice_read = 184; struct_offset.fop_iterate = 48; struct_offset.fop_iterate_shared = 56;
  struct_offset.iop_getattr = 128; struct_offset.getattr_callback_args = 4; struct_offset.getattr_function_args = 4;
  struct_offset.getattr_context_kind = 0; struct_offset.fillattr_abi = 2; struct_offset.dir_actor_abi = 0;
  struct_offset.sop_drop_inode = 32; struct_offset.sop_evict_inode = 40;
  struct_offset.dop_init = 40; struct_offset.dop_release = 48;
  struct_offset.inode_superblock = 40; struct_offset.mutex_size = 32; struct_offset.mutex_no_lockdep = 1;
  nm_owned_operation_fallback = true; lookups = 0; btf_mode = 0;
}
/* 重定位给定窗口的函数/表身份，返回其真实长度；原生代码不执行。 */
static unsigned reset(unsigned kind, uint32_t* code) {
  const uint32_t* originals[] = {init_original, clear_original, prep_original, reg_original,
    key_original, unreg_original, permission_original, native_original};
  const unsigned count[] = {19,31,11,19,23,19,7,4};
  memcpy(code,originals[kind],count[kind]*4);
  if (kind == 0) address_to(code+16,(uintptr_t)(arena+16384));
  if (kind == 3) { branch_to(code+8,down,true); branch_to(code+18,compare,true); }
  if (kind == 5) { branch_to(code+7,down,true); branch_to(code+10,valid,true); }
  if (kind == 6) branch_to(code+6,impl,true);
  if (kind == 7) branch_to(code+3,impl,true);
  return count[kind];
}
/* 直接调用所选生产识别器，返回偏移/状态；不发布对象或调用原生函数。 */
static int run(unsigned kind, const uint32_t* code) {
  int data = -1, lock, cls, offset;
  switch (kind) {
    case 0: return nm_probe_sub_inode_storage(code,(uintptr_t)(arena+16384),NULL,&data);
    case 1: return nm_find_mapping_clear_size(code);
    case 2: return nm_find_key_preparse_data(code);
    case 3: return nm_find_key_registration(code,(uintptr_t)compare,&lock,&cls,&offset);
    case 4: return nm_find_key_callback_slot(code);
    case 5: return nm_find_key_type_link(code,(uintptr_t)down,(uintptr_t)valid);
    case 6: return nm_check_split_permission(code,native);
    default: return nm_check_split_permission(permission,code);
  }
}
int main(void) {
  unsigned char storage[32768] __attribute__((aligned(4096))) = {0}; arena=storage;
  core_start=(uintptr_t)arena;core_end=(uintptr_t)(arena+sizeof(storage));
  alignment=(void*)(arena+2048); initializer=(void*)(arena+256);clearer=(void*)(arena+512);
  prep=(void*)(arena+768);reg=(void*)(arena+1024);key=(void*)(arena+1280);unreg=(void*)(arena+1536);
  permission=(void*)(arena+1792);native=(void*)(arena+1920);
  compare=(void*)(arena+4096);down=compare+4;valid=compare+8;impl=compare+12;
  free_preparse=compare+16;instantiate=compare+20;no_open=compare+24;
  for (unsigned i=0;i<28;i++) compare[i]=0xd65f03c0U;
  memcpy(alignment,align_original,sizeof(align_original));
  uint32_t* inputs[]={initializer,clearer,prep,reg,key,unreg,permission,native};
  for(unsigned i=0;i<8;i++)reset(i,inputs[i]);
  key_table[3]=(uintptr_t)prep;key_table[4]=(uintptr_t)free_preparse;key_table[5]=(uintptr_t)instantiate;
  seed();assert(nm_set_compact_operation_extents(176,216,104)==0);
  assert(struct_offset.inode_ops_size==192&&struct_offset.super_ops_size==232&&struct_offset.dentry_ops_size==128);
  const struct { unsigned field; int value; } bad_fields[]={{0,248},{1,1},{2,104},{3,120},{4,96},{5,192},{6,56},{7,64},
    {8,144},{9,3},{10,3},{11,1},{12,3},{13,1},{14,40},{15,48},{16,-1},{17,40}};
  for(unsigned i=0;i<ARRAY_SIZE(bad_fields);i++){
    seed();volatile int16_t* fields[]={&struct_offset.file_ops_size,&struct_offset.fop_io_bias,&struct_offset.fop_open,
      &struct_offset.fop_release,&struct_offset.fop_mmap,&struct_offset.fop_splice_read,&struct_offset.fop_iterate,
      &struct_offset.fop_iterate_shared,&struct_offset.iop_getattr,&struct_offset.getattr_callback_args,
      &struct_offset.getattr_function_args,&struct_offset.getattr_context_kind,&struct_offset.fillattr_abi,
      &struct_offset.dir_actor_abi,&struct_offset.sop_drop_inode,&struct_offset.sop_evict_inode,&struct_offset.dop_init,
      &struct_offset.dop_release};*fields[bad_fields[i].field]=bad_fields[i].value;
    assert(nm_set_compact_operation_extents(176,216,104)<0);
    assert(struct_offset.inode_ops_size==-1&&struct_offset.super_ops_size==-1&&struct_offset.dentry_ops_size==-1);
  }
  seed();assert(nm_set_compact_operation_extents(184,216,104)<0);
  assert(nm_set_compact_operation_extents(176,224,104)<0);assert(nm_set_compact_operation_extents(176,216,112)<0);
  uint32_t saved=alignment[2];alignment[2]^=1U<<10;assert(nm_set_compact_operation_extents(176,216,104)<0);
  alignment[2]=saved;
  const int expected[]={376,176,40,120,24,120,0,0};
  const uint32_t mutants[]={0xd503201fU,0x94000000U,0xc8087c83U};
  for(unsigned kind=0;kind<8;kind++){
    unsigned count=reset(kind,inputs[kind]);seed();assert(run(kind,inputs[kind])==expected[kind]);
    for(unsigned r=0;r<3;r++)for(unsigned i=0;i<count;i++){
      uint32_t before=inputs[kind][i];inputs[kind][i]=mutants[r];
      assert(run(kind,inputs[kind])<0);inputs[kind][i]=before;
    }
  }
  // 原生表身份及边界另测；不能仅凭STR的位置确认i_fop。
  uintptr_t* table=(void*)(arena+16384);table[96/8]=(uintptr_t)no_open;
  struct nm_initial_fops_probe probe={(uintptr_t)no_open,core_start,core_start+8192,core_end};int data=-1;
  seed();assert(nm_probe_sub_inode_storage(initializer,0,&probe,&data)==376&&data==392);
  table[96/8]=0;data=-1;assert(nm_probe_sub_inode_storage(initializer,0,&probe,&data)<0&&data==-1);
  table[96/8]=(uintptr_t)no_open;probe.end=(uintptr_t)table+239;assert(nm_probe_sub_inode_storage(initializer,0,&probe,&data)<0);
  // 标量复制只允许不覆盖值或两个参数的MOVZ，截短窗口不得跨边界。
  uint32_t gap[]={0xf9404c08U,0x52808029U,0xf9004028U};
  assert(nm_scalar_copy(gap,3,3,128)==152);assert(nm_scalar_copy(gap,2,3,128)<0);
  const uint32_t bad_gap[]={0x52808028U,0x52808020U,0x52808021U,0x94000000U,0xc8087c83U};
  for(unsigned i=0;i<ARRAY_SIZE(bad_gap);i++){gap[1]=bad_gap[i];assert(nm_scalar_copy(gap,3,3,128)<0);}
  // 完整控制布局重放；有效BTF错误不进入函数推导。
  seed();assert(nm_prepare_control_layout()==0&&struct_offset.key_type_size==136&&struct_offset.key_callbacks==24);
  seed();btf_mode=1;assert(nm_prepare_control_layout()==-EINVAL&&lookups==0);
  btf_mode=2;assert(nm_prepare_control_layout()==-ENODATA&&lookups==0);
  // 每个必要窗口贴保护页，所有重定位保持在同一映射内。
  long page=sysconf(_SC_PAGESIZE);assert(page>1024);
  unsigned char* pages=mmap(NULL,page*20,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0);
  assert(pages!=MAP_FAILED);for(unsigned i=1;i<16;i+=2)assert(!mprotect(pages+page*i,page,PROT_NONE));
  arena=pages;core_start=(uintptr_t)pages;core_end=(uintptr_t)(pages+page*20);
  compare=(void*)(pages+page*18);down=compare+4;valid=compare+8;impl=compare+12;
  for(unsigned i=0;i<16;i++)compare[i]=0xd65f03c0U;
  uint32_t* guarded_native=(void*)(pages+page*17);uint32_t* guarded_permission=guarded_native+16;
  reset(7,guarded_native);reset(6,guarded_permission);native=guarded_native;permission=guarded_permission;
  for(unsigned kind=0;kind<8;kind++){
    const unsigned counts[]={19,31,11,19,23,19,7,4};
    uint32_t* code=(void*)(pages+page*(kind*2+1)-counts[kind]*4);
    reset(kind,code);seed();assert(run(kind,code)==expected[kind]);
    for(unsigned i=0;i<counts[kind];i++){uint32_t before=code[i];code[i]=0xd503201fU;
      assert(run(kind,code)<0);code[i]=before;}
  }
  uint32_t* truncated=(void*)(pages+page-8);truncated[0]=0xf9404c08U;truncated[1]=0x52808029U;
  assert(nm_scalar_copy(truncated,2,3,128)<0);
  assert(!munmap(pages,page*20));
  puts("compact entries: sizes, source identity, zero coverage, arguments, control, BTF errors and guard pages passed");
  return 0;
}
'''
    with tempfile.TemporaryDirectory(prefix='nomount-compact-entries-') as directory:
        path = Path(directory)
        (path / 'test.c').write_text(source)
        result = subprocess.run([compiler, '-std=gnu11', '-Wall', '-Werror', '-Wno-unused-function',
                                 '-fsanitize=address,undefined', str(path / 'test.c'), '-o', str(path / 'test')],
                                text=True, capture_output=True)
        if result.returncode:
            print(result.stderr)
        result.check_returncode()
        subprocess.run([str(path / 'test')], check=True)
    if args.output:
        receipt = {'role': 'Developer', 'scope': '宿主生产函数自检；不执行原生代码，不证明真机加载/CFI',
                   'sources': {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in
                               ('nomount/nm_offsets.c', 'nomount/nm_structs.h', 'kpm_utils.h')},
                   'tool_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                   'windows': WORDS, 'result': 'PASS'}
        with args.output.open('x') as output:
            json.dump(receipt, output, ensure_ascii=False, indent=2)
            output.write('\n')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
