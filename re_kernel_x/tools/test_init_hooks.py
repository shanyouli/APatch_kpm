#!/usr/bin/env python3
"""执行生产 hook 安装／撤销路径，注入逐阶段失败并检查回调所有权。"""
import argparse
from pathlib import Path
import subprocess

from test_native_apis import function

HOST = r'''
#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <errno.h>
typedef int hook_err_t;
#define logkm(...) ((void)0)
static bool business_hooked[4];
static int attempts, fail_at, removed, order[4];
static bool active[4], foreign[4] = {true, true, true, true};
static void *binder_transaction = (void*)1, *do_send_sig_info = (void*)2;
static void *tcp_v4_do_rcv = (void*)3, *tcp_v6_do_rcv = (void*)4;
static int ipv4_version = 4, ipv6_version = 6;
static void binder_transaction_before(void) {}
static void binder_transaction_after(void) {}
static void do_send_sig_info_before(void) {}
static void tcp_rcv_before(void) {}
static int hook_wrap(void* target, int argc, void* before, void* after, void* data) {
  int index = (int)(size_t)target - 1;
  assert(index >= 0 && index < 4 && before);
  assert(argc == (index == 0 ? 5 : index == 1 ? 4 : 2));
  assert(after == (index == 0 ? binder_transaction_after : NULL));
  assert(data == (index == 2 ? &ipv4_version : index == 3 ? &ipv6_version : NULL));
  if (++attempts == fail_at) return 4090;
  assert(!active[index]); active[index] = true;
  return 0;
}
static void hook_unwrap(void* target, void* before, void* after) {
  int index = (int)(size_t)target - 1;
  assert(before && active[index] && foreign[index]);
  assert(after == (index == 0 ? binder_transaction_after : NULL));
  active[index] = false; order[removed++] = index;
}
/* PRODUCTION */
int main(void) {
  for (fail_at = 0; fail_at <= 4; fail_at++) {
    attempts = removed = 0;
    int rc = install_business_hooks();
    assert(rc == (fail_at ? -23 : 0));
    int installed = fail_at ? fail_at - 1 : 4;
    if (!fail_at) remove_business_hooks();
    assert(removed == installed);
    for (int i = 0; i < installed; i++) assert(order[i] == installed - i - 1);
    for (int i = 0; i < 4; i++) assert(!active[i] && !business_hooked[i] && foreign[i]);
    remove_business_hooks();
    assert(removed == installed);
  }
  fail_at = 0; attempts = removed = 0;
  tcp_v4_do_rcv = NULL;
  assert(install_business_hooks() == -ENOENT);
  assert(attempts == 2 && removed == 2 && order[0] == 1 && order[1] == 0);
  remove_business_hooks(); assert(removed == 2);
  puts("PASS: partial failure, reverse rollback, foreign callbacks, repeated exit, missing target");
}
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    source = (Path(__file__).resolve().parents[1] / 're_kernel.c').read_text()
    names = ('install_business_hook', 'remove_business_hooks', 'install_business_hooks')
    if 'static int install_business_hook(' in source:
        code = '\n\n'.join(function(source, name) for name in names)
    else:
        # 旧实现也执行真实安装／退出片段，证明中途失败没有回滚。
        install = source[source.index('  hook_func(binder_transaction, 5,'):source.index('  rc = start_rekernel_genl_server();')]
        cleanup = source[source.index('  unhook_func(binder_transaction);'):source.index('\n  return 0;\n}\n\nKPM_INIT')]
        code = r'''
#define hook_func(target, argc, before, after, data) \
  if (hook_wrap(target, argc, before, after, data)) return -23
static void unhook(void* target) {
  int index = (int)(size_t)target - 1;
  foreign[index] = false;
  active[index] = false;
}
#define unhook_func(target) if (target) unhook(target)
''' + '\nstatic void remove_business_hooks(void) {\n' + cleanup + '\n}\n'
        code += '\nstatic int install_business_hooks(void) {\n' + install + '\nreturn 0;\n}\n'
    fixture = args.output / 'hooks.c'
    fixture.write_text(HOST.replace('/* PRODUCTION */', code))
    binary = args.output / 'hooks'
    subprocess.run(['clang', '-Wall', '-Werror', '-Wno-unused-function', '-fsanitize=address,undefined', str(fixture), '-o', str(binary)], check=True)
    subprocess.run([str(binary.resolve())], check=True)


if __name__ == '__main__':
    main()
