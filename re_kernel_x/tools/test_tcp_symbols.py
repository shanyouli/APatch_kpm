#!/usr/bin/env python3
"""用目标符号名及 KP 生产后缀查询代码复现 TCP 初始化失败。"""
import argparse
from pathlib import Path
import subprocess

from test_native_apis import function

HOST = r'''
#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#define VERSION(a,b,c) (((a) << 16) | ((b) << 8) | (c))
#define logkm(...) ((void)0)
#define pr_info(...) ((void)0)
#define lookup_name(n) n = (typeof(n))kallsyms_lookup_name(#n); if (!n) return -21
struct module;
struct suffix_lookup { const char* base; unsigned long addr; };
static int kver = VERSION(4,14,186);
static bool cfi_bypass = true;
static void *tcp_v4_do_rcv, *tcp_v6_do_rcv, *genl_rcv_msg;
static const char* genl;
static const char* v4;
static const char* v6;
static unsigned long kallsyms_lookup_name(const char* name) {
  if (v4 && !strcmp(name, v4)) return 0x1000;
  if (v6 && !strcmp(name, v6)) return 0x2000;
  if (genl && !strcmp(name, genl)) return 0x3000;
  return 0;
}
static int enumerate(int (*cb)(void*, const char*, struct module*, unsigned long), void* data) {
  if (v4 && cb(data, v4, NULL, 0x1000)) return 1;
  if (v6 && cb(data, v6, NULL, 0x2000)) return 1;
  if (genl && cb(data, genl, NULL, 0x3000)) return 1;
  return 0;
}
static int (*kallsyms_on_each_symbol)(int (*)(void*, const char*, struct module*, unsigned long), void*) = enumerate;
/* KP */
static int resolve_tcp(void) {
/* MODULE */
  return 0;
}
static int resolve_genl(void) {
/* GENL */
  return 0;
}
static void check(const char* ipv4, const char* ipv6, int expected) {
  v4 = ipv4; v6 = ipv6;
  tcp_v4_do_rcv = tcp_v6_do_rcv = NULL;
  assert(resolve_tcp() == expected);
  if (!expected) assert(tcp_v4_do_rcv == (void*)0x1000 && tcp_v6_do_rcv == (void*)0x2000);
}
int main(void) {
  check("tcp_v4_do_rcv", "tcp_v6_do_rcv", 0);
  // 来自用户 4.14.186 bugreport 的实际符号名。
  check("tcp_v4_do_rcv", "tcp_v6_do_rcv$ee27caa43c353d9731099fb1ec6d2c19", 0);
  check("tcp_v4_do_rcv.llvm.123", "tcp_v6_do_rcv$ee27caa43c353d9731099fb1ec6d2c19", 0);
  check("tcp_v4_do_rcv", NULL, -21);
  check(NULL, "tcp_v6_do_rcv", -21);
  check("tcp_v4_do_rcv", "tcp_v6_do_rcv_other", -21);
  cfi_bypass = false;
  check("tcp_v4_do_rcv", "tcp_v6_do_rcv$ee27caa43c353d9731099fb1ec6d2c19", -21);
  check("tcp_v4_do_rcv", "tcp_v6_do_rcv", 0);
  cfi_bypass = true;
  genl = "genl_rcv_msg$1309a1e4f601a8e6c1715537ac333319";
  assert(!resolve_genl() && genl_rcv_msg == (void*)0x3000);
  genl = "genl_rcv_msg";
  assert(!resolve_genl() && genl_rcv_msg == (void*)0x3000);
  genl = NULL;
  assert(resolve_genl() == -21 && !genl_rcv_msg);
  puts("PASS: TCP/Genl exact names, target CFI hashes, LLVM suffix, missing/nearby symbol, unavailable suffix lookup");
}
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    root = Path(__file__).resolve().parents[2]
    source = (root / 're_kernel_x/re_kernel.c').read_text()
    block = source.split('  kfunc_lookup_name(sock_i_uid);', 1)[1].split('#ifdef CONFIG_DEBUG_CMDLINE', 1)[0]
    kp = (root / 'KernelPatch/kernel/base/start.c').read_text()
    kp = kp.replace('unsigned long kallsyms_lookup_name_by_suffix(', 'static unsigned long kallsyms_lookup_name_by_suffix(')
    names = ('suffix_contains_cfi', 'symbol_has_compiler_suffix', 'lookup_suffix_cb',
             'lookup_suffix_cb_nomod', 'kallsyms_lookup_name_by_suffix')
    production = '\n\n'.join(function(kp, name) for name in names)
    path, binary = args.output / 'tcp.c', args.output / 'tcp'
    genl = '  genl_rcv_msg =' + source.split('  genl_rcv_msg =', 1)[1].split('  if (!kfunc(kfree_skb)', 1)[0]
    path.write_text(HOST.replace('/* KP */', production).replace('/* MODULE */', block).replace('/* GENL */', genl))
    build = subprocess.run(['clang', '-Wall', '-Werror', '-Wno-unused-function', '-fsanitize=address,undefined', str(path), '-o', str(binary)], capture_output=True, text=True)
    (args.output / 'build.log').write_text(build.stdout + build.stderr)
    assert build.returncode == 0, build.stderr
    run = subprocess.run([str(binary.resolve())], capture_output=True, text=True)
    (args.output / 'run.log').write_text(run.stdout + run.stderr)
    assert run.returncode == 0, run.stdout + run.stderr
    print(run.stdout.strip())


if __name__ == '__main__':
    main()
