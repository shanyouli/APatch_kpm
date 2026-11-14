#!/usr/bin/env python3
"""核验kvfree内联范围的旧SCS／无SCS双返回入口；不执行原生代码或更改已有Oracle。"""
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
# miuiportspatched.img的kvfree@Image+0x361450，完整双返回函数16条。
TARGET = (0xa9bf7bfd, 0x910003fd, 0xb25963e8, 0xf2a10008,
          0xeb08001f, 0x54000103, 0x92a80028, 0xf2dff7c8,
          0xeb08001f, 0x54000088, 0x9400b854, 0xa8c17bfd,
          0xd65f03c0, 0x9400f786, 0xa8c17bfd, 0xd65f03c0)


def main():
    """提取当前生产函数，用真实目标词及旧14条契约执行正反例，成功0，失败传播。

    --output可选，排他保存源码、工具、窗口指纹；使用已有Clang和临时文件。
    BL仅重定位到宿主映射的具名占位，不执行目标指令或释放内核内存。
    """
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    compiler = shutil.which('clang')
    if not compiler:
        raise RuntimeError('没有已安装的宿主Clang，未执行测试')
    offsets = (ROOT / 'nomount/nm_offsets.c').read_text()
    utils = (ROOT / 'kpm_utils.h').read_text().split('// instruction\n', 1)[1].rsplit('#endif', 1)[0]
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
    source += utils + function(offsets, 'nm_find_vmalloc_range')
    source += 'static const uint32_t target[16]={' + ','.join(hex(word) for word in TARGET) + '};\n'
    source += r'''
/* 在宿主映射内重定位BL，位移有界且对齐；不调用地址参数。 */
static void call_to(uint32_t* at, uintptr_t to) {
  intptr_t delta=(intptr_t)to-(intptr_t)(uintptr_t)at;
  assert(delta%4==0 && delta>=-(1L<<27) && delta<(1L<<27));
  *at=0x94000000U|((uint32_t)(delta/4)&0x3ffffffU);
}
/* 真实16条或旧14条入口的构造，旧比较／分支契约原样保持。 */
static void reset(uint32_t* code,bool legacy,uintptr_t vfree,uintptr_t kfree) {
  if (legacy) {
    code[0]=0xf800865eU;code[1]=0xa9bf7bfdU;code[2]=0x910003fdU;
    memcpy(code+3,target+2,8*4);code[6]=0x540000e3U;code[10]=0x54000068U;
    call_to(code+11,vfree);code[12]=0x14000002U;call_to(code+13,kfree);
  } else { memcpy(code,target,sizeof(target));call_to(code+10,vfree);call_to(code+13,kfree); }
}
int main(void) {
  long page=sysconf(_SC_PAGESIZE);assert(page>256);
  unsigned char* pages=mmap(NULL,page*4,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0);
  assert(pages!=MAP_FAILED && !mprotect(pages+page,page,PROT_NONE));
  uintptr_t vfree=(uintptr_t)(pages+page*2),kfree=vfree+32;
  uint32_t* code=(void*)(pages+128);uintptr_t range[2];
  const uint32_t mutants[]={0xd503201fU,0x94000000U,0xc8087c83U};
  for(unsigned legacy=0;legacy<2;legacy++){
    unsigned count=legacy?14:16;reset(code,legacy,vfree,kfree);
    assert(nm_find_vmalloc_range(code,vfree,kfree,range)==0);
    assert(range[0]==0xffffff8008000000ULL && range[1]==0xffffffbebffeffffULL);
    for(unsigned m=0;m<3;m++)for(unsigned i=0;i<count;i++){
      uint32_t saved=code[i];code[i]=mutants[m];range[0]=7;range[1]=9;
      assert(nm_find_vmalloc_range(code,vfree,kfree,range)<0 && range[0]==7 && range[1]==9);code[i]=saved;
    }
    assert(nm_find_vmalloc_range(code,0,kfree,range)==-ENOENT);
    assert(nm_find_vmalloc_range(code,vfree,0,range)==-ENOENT);
    assert(nm_find_vmalloc_range(NULL,vfree,kfree,range)==-ENOENT);
    // 完整常量来自目标指令，MOVK变化必须反映到输出，不能硬编码本目标范围。
    unsigned patch=legacy?4:3;uint32_t saved=code[patch];
    code[patch]=(code[patch]&~(0xffffU<<5))|(0x900U<<5);
    assert(nm_find_vmalloc_range(code,vfree,kfree,range)==0 && range[0]==0xffffff8009000000ULL);
    code[patch]=saved;
    // 截断宽度、比较源、条件/目标、调用身份和上下界分别拒绝。
    const struct { unsigned at; uint32_t mask; } changes[]={{2,1U<<31},{3,1U<<31},{4,1U<<5},
      {4,1U<<16},{5,1U},{5,1U<<5},{6,1U<<31},{7,1U<<31},{8,1U<<5},{9,1U},{9,1U<<5}};
    for(unsigned i=0;i<sizeof(changes)/sizeof(changes[0]);i++){
      unsigned at=changes[i].at+(legacy?1:0);saved=code[at];code[at]^=changes[i].mask;
      assert(nm_find_vmalloc_range(code,vfree,kfree,range)<0);code[at]=saved;
    }
    assert(nm_find_vmalloc_range(code,vfree+4,kfree,range)<0);
    assert(nm_find_vmalloc_range(code,vfree,kfree+4,range)<0);
    // 两个范围交换仍是合法的常量指令，必须因倒置失败。
    unsigned low=legacy?3:2,high=legacy?7:6;uint32_t first=code[low],patch_word=code[low+1];
    code[low]=code[high];code[low+1]=code[high+1];code[high]=first;code[high+1]=patch_word;
    assert(nm_find_vmalloc_range(code,vfree,kfree,range)<0);reset(code,legacy,vfree,kfree);
    // 固定窗口贴保护页，正例及逐条反例不能读取到下一页。
    uint32_t* guarded=(void*)(pages+page-count*4);reset(guarded,legacy,vfree,kfree);
    assert(nm_find_vmalloc_range(guarded,vfree,kfree,range)==0);
    for(unsigned i=0;i<count;i++){saved=guarded[i];guarded[i]=0xd503201fU;
      assert(nm_find_vmalloc_range(guarded,vfree,kfree,range)<0);guarded[i]=saved;}
  }
  assert(!munmap(pages,page*4));
  puts("vmalloc entry: target16, legacy14, constants, width, dispatch, output and guard pages passed");
  return 0;
}
'''
    with tempfile.TemporaryDirectory(prefix='nomount-vmalloc-entry-') as directory:
        path = Path(directory)
        (path / 'test.c').write_text(source)
        subprocess.run([compiler, '-std=gnu11', '-Wall', '-Werror', '-Wno-unused-function',
                        '-fsanitize=address,undefined', str(path / 'test.c'), '-o', str(path / 'test')], check=True)
        subprocess.run([str(path / 'test')], check=True)
    if args.output:
        receipt = {'role': 'Developer', 'scope': '纯识别器宿主自检，不执行原生函数或证明RCU释放行为',
                   'production_sha256': hashlib.sha256(offsets.encode()).hexdigest(),
                   'utils_sha256': hashlib.sha256((ROOT / 'kpm_utils.h').read_bytes()).hexdigest(),
                   'tool_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                   'target_words': TARGET, 'new_window': 16, 'legacy_window': 14, 'result': 'PASS'}
        with args.output.open('x') as output:
            json.dump(receipt, output, ensure_ascii=False, indent=2)
            output.write('\n')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
