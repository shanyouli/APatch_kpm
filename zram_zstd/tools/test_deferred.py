#!/usr/bin/env python3
"""Developer 自检：只以本地 clang 验证生产启动控制及实际 KP 链分发，不下载资源。

激活函数仅作模型；完整 Crypto/codec 回归仍由原测试负责，需要已准备的 ZSTD 资源。
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess

from host_native import hook_frame


PRELUDE = '''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
#define printk printf
typedef struct { uint64_t arg0, arg1, ret; } hook_fargs2_t;
'''


def digest(path):
    """读取 path 并返回 SHA-256 字符串；不修改文件，读取错误向上传播。"""
    return hashlib.sha256(path.read_bytes()).hexdigest()


def chain_source(root):
    """提取 SDK 完整 _transit4/hook_chain_add，返回仅移除宿主不支持节名的代码。"""
    text = (root / 'KernelPatch/kernel/base/hook.c').read_text()
    start = text.index('// transit4')
    end = text.index('#ifndef KP_HOOK_EXTERNAL_CHAIN_PREPARE', start)
    transit = text[start:end].replace('__attribute__((section(".transit4.text")))', '')
    start = text.index('hook_err_t hook_chain_add(')
    end = text.index('KP_EXPORT_SYMBOL(hook_chain_add);', start)
    return transit + '\n' + text[start:end]


def startup_source(module):
    """逐段复制当前生产状态/启动/退出代码，返回文本；不替换逻辑或原 Oracle 断言。"""
    text = (module / 'zram_zstd.c').read_text()
    state = text[text.index('enum zs_deferred_state'):text.index('// 注册前取得一次')]
    start = text.index('static void zram_zstd_after_kernel_init(')
    end = text.index('static long zram_zstd_ctl0(', start)
    startup = text[start:end]
    start = text.index('static long zram_zstd_exit(')
    end = text.index('KPM_INIT(', start)
    exit_function = text[start:end]
    log = next(line for line in text.splitlines() if line.startswith('#define logkm('))
    return log + '\nstatic bool registered;\n' + state + startup + exit_function


def build_source(module):
    """组合原样生产控制、实际分发和模型夹具，返回源码；不准备或链接外部编解码库。"""
    fixture = (module / 'tools/deferred_fixture.c').read_text()
    fixture = fixture.replace('/* HOOK_CHAIN_CODE */', chain_source(module.parent))
    fixture = fixture.replace('/* PRODUCTION_STARTUP */', startup_source(module))
    return hook_frame(PRELUDE + fixture)


def main():
    """用 --output 的新目录运行本地 ASan/UBSan，生成日志与限定范围回执；失败不标通过。"""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    module = Path(__file__).resolve().parents[1]
    root = module.parent
    source = build_source(module)
    path = args.output / 'fixture.c'
    path.write_text(source)
    binary = args.output / 'fixture'
    result = subprocess.run(['clang', '-O1', '-g', '-Wall', '-Werror', '-Wno-unused-function',
                             '-fsanitize=address,undefined', '-fno-omit-frame-pointer', str(path), '-o', str(binary)],
                            capture_output=True, text=True)
    (args.output / 'compile.log').write_text(result.stdout + result.stderr)
    if result.returncode:
        raise RuntimeError(result.stderr)
    result = subprocess.run([str(binary)], capture_output=True, text=True)
    (args.output / 'stdout.txt').write_text(result.stdout)
    (args.output / 'stderr.txt').write_text(result.stderr)
    result.check_returncode()
    if result.stderr:
        raise RuntimeError(result.stderr)
    paths = [Path(__file__), module / 'zram_zstd.c', module / 'tools/deferred_fixture.c',
             module / 'tools/host_native.py', root / 'KernelPatch/kernel/base/hook.c',
             root / 'KernelPatch/kernel/include/hook.h']
    receipt = {'scope': 'Developer ASan/UBSan production startup-control and real-KP-dispatch host test; activation modeled',
               'not_covered': ['real Crypto registration/codec', 'native ABI/CFI/locks', 'device boot/swap'],
               'result': 'PASS', 'sources': {str(p.relative_to(root)): digest(p) for p in paths},
               'generated_fixture_sha256': digest(path), 'assert_sites': len(re.findall(r'\bassert\s*\(', source)),
               'stdout': result.stdout}
    (args.output / 'receipt.json').write_text(json.dumps(receipt, ensure_ascii=False, indent=2) + '\n')
    print(result.stdout, end='')


if __name__ == '__main__':
    main()
