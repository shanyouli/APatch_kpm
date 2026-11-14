#!/usr/bin/env python3
"""按原始公开声明与目标配置编译核对compact布局；不证明参考树是镜像准确源码。"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[2]
REFERENCE_COMMIT = '4b6c276ac99cad51bf4d0bd6ea12a32847403b42'
HEADERS = {
    'include/linux/fs.h': 'fb97aa1016e873b1185946414f57774fbae8f382f46ccca6f1abb255ac9abec8',
    'include/linux/dcache.h': '06c43496effe6f3ba7d747e5726ab9b049bbef35994021550f569c6282b13272',
    'include/linux/rwsem.h': '92281c7272bd9f288acc0fb2699103f8ec67befd0482dbf917b7950cf5d32c94',
    'include/linux/osq_lock.h': 'a2661ef30af34510881fd254c84972bfeae5dd6d579ffe7c174ae3c1f3cfcd10',
    'include/linux/radix-tree.h': '4ea147fa095f6f65acd8ba75dd43c3c84a5397a1252e1427d54db613df627ca8',
    'include/linux/rbtree.h': 'fa184923c6ef8fb099386be78682d70a970a7e4e7c88bd042630af41137153fd',
    'arch/arm64/include/asm/cache.h': '563033039dee71917234045728334f7481ce9d18da0fa83dd00541337d2f9be1',
    'include/linux/cache.h': 'a73445aa4721fd24bebcf45835344ffe3e1163fb56bec03f3b26afdfbd771e15',
}


def declaration(text, name):
    """提取text中具名完整struct及尾随属性/条件字段，缺失或重复时拒绝；不改成员。"""
    starts = list(re.finditer(r'\bstruct\s+' + re.escape(name) + r'\s*\{', text))
    if len(starts) != 1:
        raise ValueError(f'完整声明不唯一: {name}')
    at = starts[0].end()
    depth = 1
    while depth:
        depth += (text[at] == '{') - (text[at] == '}')
        at += 1
    end = text.index(';', at)
    return text[starts[0].start():end + 1] + '\n'


def main():
    """核对固定源哈希/配置后编译原声明并比较生产类型；成功0，错误传播异常。

    参数提供参考目录、从目标取得的配置和新输出目录；原始函数指针/条件字段/属性
    全部保留。基本原语使用已核对ARM64宽度的桩，桩不代替来源对应性或原生调用证明。
    """
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--reference-root', type=Path, required=True)
    parser.add_argument('--config', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    compiler = shutil.which('clang')
    if not compiler:
        raise RuntimeError('没有已安装的宿主Clang，未执行核验')
    texts = {}
    for name, expected in HEADERS.items():
        data = (args.reference_root / name).read_bytes()
        if hashlib.sha256(data).hexdigest() != expected:
            raise ValueError(f'参考源字节与固定提交不符: {name}')
        texts[name] = data.decode()
    config = args.config.read_text()
    enabled = set(re.findall(r'^(CONFIG_[A-Z0-9_]+)=y$', config, re.M))
    required = {'CONFIG_MMU', 'CONFIG_QUOTA', 'CONFIG_RWSEM_XCHGADD_ALGORITHM',
                'CONFIG_RWSEM_SPIN_ON_OWNER', 'CONFIG_MTK_TASK_TURBO'}
    excluded = {'CONFIG_GCC_PLUGINS', 'CONFIG_DEBUG_LOCK_ALLOC', 'CONFIG_DEBUG_SPINLOCK'}
    if not required <= enabled or excluded & enabled:
        raise ValueError('目标配置不符合本完整声明契约，不能套用compact布局')
    if '#define L1_CACHE_SHIFT\t\t6' not in texts['arch/arm64/include/asm/cache.h']:
        raise ValueError('参考对齐宏链发生变化')
    specs = [('include/linux/osq_lock.h', 'optimistic_spin_queue'),
             ('include/linux/radix-tree.h', 'radix_tree_root'),
             ('include/linux/rbtree.h', 'rb_root'), ('include/linux/rbtree.h', 'rb_root_cached'),
             ('include/linux/rwsem.h', 'rw_semaphore'), ('include/linux/fs.h', 'address_space'),
             ('include/linux/fs.h', 'file_operations'), ('include/linux/fs.h', 'inode_operations'),
             ('include/linux/fs.h', 'super_operations'), ('include/linux/dcache.h', 'dentry_operations')]
    decls = ''.join(declaration(texts[name], symbol) for name, symbol in specs)
    forwards = ''.join('struct ' + name + ';\n' for name in sorted(set(re.findall(r'\bstruct\s+(\w+)', decls))))
    source = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#define __user
#define __rcu
#define __randomize_layout
#define L1_CACHE_SHIFT 6
#define L1_CACHE_BYTES (1 << L1_CACHE_SHIFT)
#define SMP_CACHE_BYTES L1_CACHE_BYTES
#define ____cacheline_aligned __attribute__((aligned(SMP_CACHE_BYTES)))
typedef uint8_t u8; typedef uint16_t u16; typedef uint32_t u32; typedef uint64_t u64;
typedef uint16_t umode_t; typedef uint32_t dev_t; typedef uint32_t gfp_t; typedef uint32_t errseq_t;
typedef unsigned long pgoff_t; typedef long ssize_t; typedef long long loff_t; typedef void* fl_owner_t;
typedef struct { int counter; } atomic_t;
typedef struct { long counter; } atomic_long_t;
typedef uint32_t spinlock_t; typedef uint32_t raw_spinlock_t;
struct list_head { struct list_head* next; struct list_head* prev; };
'''
    source += ''.join('#define ' + name + ' 1\n' for name in sorted(enabled)) + forwards + decls
    source += '#include "nm_structs.h"\n'
    source += r'''
int main(void) {
  assert(sizeof(void*) == 8 && sizeof(long) == 8 && sizeof(atomic_long_t) == 8 && sizeof(spinlock_t) == 4);
  assert(sizeof(struct file_operations) == sizeof(struct nm_compact_file_operations));
  assert(offsetof(struct inode_operations, getattr) == offsetof(struct nm_inode_android_link_prefix, getattr));
  assert(offsetof(struct inode_operations, set_acl) - offsetof(struct inode_operations, getattr)
         == offsetof(struct nm_compact_inode_tail, set_acl));
  assert(sizeof(struct inode_operations) == ((offsetof(struct inode_operations, getattr)
         + sizeof(struct nm_compact_inode_tail) + 63) & ~63U));
  assert(sizeof(struct super_operations) == sizeof(struct nm_compact_super_operations));
  assert(offsetof(struct super_operations, nr_cached_objects)
         == offsetof(struct nm_compact_super_operations, tail.reporting.cache.nr_cached_objects));
  assert(offsetof(struct dentry_operations, d_release) == sizeof(struct nm_dentry_control_ops) + sizeof(void*));
  assert(offsetof(struct dentry_operations, d_canonical_path) - offsetof(struct dentry_operations, d_release)
         == offsetof(struct nm_compact_dentry_tail, canonical_path));
  assert(sizeof(struct dentry_operations) == ((offsetof(struct dentry_operations, d_release)
         + sizeof(struct nm_compact_dentry_tail) + 63) & ~63U));
  assert(sizeof(struct rw_semaphore) == sizeof(struct nm_compact_rwsem));
  assert(offsetof(struct rw_semaphore, turbo_owner) == offsetof(struct nm_compact_rwsem, turbo_owner));
  assert(sizeof(struct address_space) == sizeof(struct nm_compact_address_space));
  assert(offsetof(struct address_space, i_mmap_rwsem) == offsetof(struct nm_compact_address_space, mmap_sem));
  assert(offsetof(struct address_space, private_list) == offsetof(struct nm_compact_address_space, private_next));
  assert(offsetof(struct address_space, wb_err) == offsetof(struct nm_compact_address_space, wb_err));
  printf("reference layouts: file=%zu inode=%zu super=%zu dentry=%zu rwsem=%zu mapping=%zu\n",
         sizeof(struct file_operations), sizeof(struct inode_operations), sizeof(struct super_operations),
         sizeof(struct dentry_operations), sizeof(struct rw_semaphore), sizeof(struct address_space));
  return 0;
}
'''
    args.output.mkdir(parents=True, exist_ok=False)
    c = args.output / 'reference.c'
    c.write_text(source)
    result = subprocess.run([compiler, '-std=gnu11', '-Wall', '-Werror', '-Wno-unused-function',
                             '-fsanitize=address,undefined', '-I' + str(ROOT / 'nomount'), str(c),
                             '-o', str(args.output / 'reference')], text=True, capture_output=True)
    (args.output / 'compile.log').write_text(result.stdout + result.stderr)
    result.check_returncode()
    result = subprocess.run([str(args.output / 'reference')], text=True, capture_output=True)
    (args.output / 'run.log').write_text(result.stdout + result.stderr)
    result.check_returncode()
    receipt = {'role': 'Developer', 'reference_commit': REFERENCE_COMMIT, 'reference_headers': HEADERS,
               'config_sha256': hashlib.sha256(args.config.read_bytes()).hexdigest(),
               'production_structs_sha256': hashlib.sha256((ROOT / 'nomount/nm_structs.h').read_bytes()).hexdigest(),
               'tool_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
               'scope': '原始完整声明编译及配置核对；原语桩只约束宽度，不证明准确构建源码或原生ABI',
               'result': result.stdout.strip()}
    (args.output / 'receipt.json').write_text(json.dumps(receipt, ensure_ascii=False, indent=2) + '\n')
    print(result.stdout.strip())


if __name__ == '__main__':
    main()
