#!/usr/bin/env python3
"""执行生产函数的宿主负例；可选交叉核对用户指定 Image 的指令窗口。"""
import argparse
import json
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / 'selinux_hook.c'


def function(text, name):
    import re
    match = re.search(r'static [^;{}\n]+\b' + re.escape(name) + r'\([^;]*?\)\s*(?://[^\n]*\n\s*)?\{', text)
    if not match:
        raise ValueError(name)
    start = match.start()
    end = match.end()
    depth = 1
    while depth:
        depth += (text[end] == '{') - (text[end] == '}')
        end += 1
    return text[start:end]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', type=Path)
    parser.add_argument('--symbols', type=Path)
    args = parser.parse_args()
    text = SOURCE.read_text()
    prelude = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <errno.h>
typedef uint32_t u32;
#define READ_ONCE(x) (x)
#define WRITE_ONCE(x,v) ((x)=(v))
struct { int16_t file_private_data; } struct_offset;
static void *g_status_open, *g_fake_status_page=(void*)0x1000;
static bool g_status_open_redirect_hooked, g_queries_hooked, g_compute_hooked, g_string_hooked;
static void *g_clean_policydb;
static bool supported=true;
static bool clean_policydb_redirect_supported(void) { return supported; }
typedef enum { SEL_HOOK_STATE_NORMAL, SEL_HOOK_STATE_POLICYDB_REQ, SEL_HOOK_STATE_UNSUPORRT } sel_hook_state_t;
static u32 read_code[4]={0xa9bf7bfd,0x910003fd,0xf9406408,0};
static u32 mmap_code[4]={0xa9bf7bfd,0x910003fd,0xf9406409,0};
static u32 open_code[20];
static bool missing, fault;
static size_t runtime_page_size(void) { return 4096; }
static void *lookup_name_optional_suffix(const char *s) {
 if (missing) return 0;
 return strstr(s,"read_handle") ? read_code : strstr(s,"mmap_handle") ? mmap_code : open_code;
}
static long copy_impl(void *dst,const void *src,size_t size) {
 if(fault) return -EFAULT; memcpy(dst,src,size); return 0;
}
static long (*copy_from_kernel_nofault_fn)(void*,const void*,size_t)=copy_impl;
static unsigned uid=10000;
struct policydb;
struct policy_file { char *data; size_t len; };
#define CLEAN_POLICYDB_ALLOC_SIZE 0x4000
#define pr_warn(...) ((void)0)
#define pr_info(...) ((void)0)
static char policy_memory[CLEAN_POLICYDB_ALLOC_SIZE];
static void *g_clean_policy_blob;
static size_t g_clean_policy_len;
static bool g_clean_policydb_direct;
static int g_policy_error=-EAGAIN, parse_error;
static void *alloc_impl(unsigned long n) { return policy_memory; }
static void (*vfree_fn)(const void*)=0;
static void zero_bytes(void *p,size_t n) { memset(p,0,n); }
static int parse_impl(struct policydb *p,struct policy_file *f) { return parse_error; }
static void destroy_impl(struct policydb *p) { }
static void *(*vmalloc_fn)(unsigned long)=alloc_impl;
static int (*policydb_read_fn)(struct policydb*,struct policy_file*)=parse_impl;
static void (*policydb_destroy_fn)(struct policydb*)=destroy_impl;
static unsigned current_uid(void) { return uid; }
static bool should_bypass_clean_filter(unsigned u) { return u<10000; }
static void *page_impl(const void *v) { return v ? (void*)0x2000 : 0; }
static void *(*vmalloc_to_page_fn)(const void*)=page_impl;
typedef struct { unsigned long ret,arg1; } hook_fargs2_t;
'''
    functions = '\n'.join(function(text, name) for name in [
        'validate_status_layout', 'after_sel_open_handle_status', 'module_get_working_mode',
        'append_u32', 'append_status_field', 'try_load_clean_policydb_from_blob'])
    tests = r'''
int main(void) {
 open_code[5]=0xaa0103f3; open_code[18]=0xf9006675;
 assert(validate_status_layout()); assert(struct_offset.file_private_data==200);
 read_code[2]^=0x400; assert(!validate_status_layout()); read_code[2]^=0x400;
 mmap_code[2]^=0x400; assert(!validate_status_layout()); mmap_code[2]^=0x400;
 open_code[18]=0; assert(!validate_status_layout()); open_code[18]=0xf9006675;
 missing=true; assert(!validate_status_layout()); missing=false;
 fault=true; assert(!validate_status_layout()); fault=false;
 char file[256]={0}; hook_fargs2_t a={.arg1=(uintptr_t)file};
 after_sel_open_handle_status(&a,0); assert(*(void**)(file+200)==(void*)0x2000);
 *(void**)(file+200)=0; uid=0; after_sel_open_handle_status(&a,0); assert(!*(void**)(file+200));
 uid=10000; a.ret=1; after_sel_open_handle_status(&a,0); assert(!*(void**)(file+200));
 assert(module_get_working_mode()==SEL_HOOK_STATE_UNSUPORRT);
 g_queries_hooked=g_compute_hooked=g_string_hooked=true;
 assert(module_get_working_mode()==SEL_HOOK_STATE_POLICYDB_REQ);
 g_clean_policydb=(void*)1; assert(module_get_working_mode()==SEL_HOOK_STATE_UNSUPORRT);
 g_status_open_redirect_hooked=true; assert(module_get_working_mode()==SEL_HOOK_STATE_NORMAL);
 g_clean_policydb=0; try_load_clean_policydb_from_blob("absent"); assert(!g_clean_policydb);
 g_clean_policy_blob=(void*)1; g_clean_policy_len=100;
 parse_error=-EINVAL; try_load_clean_policydb_from_blob("bad"); assert(!g_clean_policydb && g_policy_error==-EINVAL);
 assert(module_get_working_mode()==SEL_HOOK_STATE_POLICYDB_REQ);
 parse_error=0; try_load_clean_policydb_from_blob("ok"); assert(g_clean_policydb && !g_policy_error);
 char out[16]={0}; int n=append_status_field(out,0,sizeof(out),"errno",22);
 assert(n==8 && !memcmp(out,"errno=22",8));
 assert(append_status_field(out,-1,sizeof(out),"x",1)==-EINVAL);
 assert(append_status_field(out,0,2,"x",1)==-EINVAL);
 assert(append_u32(out,0,sizeof(out),4294967295u)==10);
 return 0;
}
'''
    with tempfile.TemporaryDirectory() as temp:
        c = Path(temp) / 'test.c'
        binary = Path(temp) / 'test'
        c.write_text(prelude + functions + tests)
        subprocess.run(['clang', '-std=gnu11', '-fsanitize=address,undefined', str(c), '-o', str(binary)], check=True)
        subprocess.run([str(binary)], check=True)
    print('PASS: 生产布局校验、缺符号/读失败/指令冲突、UID/打开失败、mode 状态与输出边界')
    if args.image:
        if not args.symbols:
            parser.error('--image 需要 --symbols')
        image = args.image.read_bytes()
        symbols = json.loads(args.symbols.read_text())
        for name, indexes in [('sel_read_handle_status', {0:0xa9bf7bfd,1:0x910003fd,2:0xf9406408}),
                              ('sel_mmap_handle_status', {0:0xa9bf7bfd,1:0x910003fd,2:0xf9406409}),
                              ('sel_open_handle_status', {5:0xaa0103f3,18:0xf9006675})]:
            matches = [a for a, _, n in symbols if (n == name or n.startswith(name+'$') or n.startswith(name+'.')) and not n.endswith('.cfi_jt')]
            assert len(matches)==1, (name,matches)
            for index, word in indexes.items():
                offset = matches[0]+4*index
                assert int.from_bytes(image[offset:offset+4],'little')==word, (name,index)
        print('PASS: 指定目标 Image 与生产校验窗口一致')


if __name__ == '__main__':
    main()
