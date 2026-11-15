#!/usr/bin/env python3
"""用指定 4.14.186 boot 的短函数指令执行 rekx 生产 Genl 推导。"""
import argparse
from pathlib import Path
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 're_kernel/tools'))
from test_genl_offsets import instruction_source, offset_source

# boot SHA-256: f54c8864b78e10f1ae8aa310ae1862dd31370b316a47d49cf4ac3616444be656
# 函数体文件偏移分别为 0x1184a04、0x1184b20、0x11857f4；不是 CFI 跳板。
WORDS = {
    'genlmsg_put': 'a9ba7bfd a9016ffc a90267fa a9035ff8 a90457f6 a9054ff4 910003fd b9409409 2940207a 2a0503f3 2a0403f6 aa0303f4 2a0203f5 2a0103f7 34000069 2a1f03e9 14000003 295b240a 4b0a0129 11005d0a 121e7559 6b19013f 540002cb 2a1903e1 1100111b',
    'genlmsg_multicast_allns': 'a9bb7bfd a90167fa a9025ff8 a90357f6 a9044ff4 910003fd b9406418 2a0403f4 2a0303f6 2a0203f5 aa0003f7 6b03031f aa0103f3 54000088 d00098a8 397e4d09 34000869 6b16031f 540009a9 d000a4b9 911de339 b9406ae8 f940033a 0b160116 eb19035f 54000380 aa1f03f7 2a1f03f8 14000006 52800038 d1006357 f940035a',
    'genl_pernet_exit': 'a9be7bfd f9000bf3 910003fd f9408408 aa0003f3 b4000088 f9413100 b4000040',
}
HOST = r'''
#include <assert.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
typedef uint32_t u32;
#define ARRAY_SIZE(a) (sizeof(a)/sizeof((a)[0]))
#define logkm(...) ((void)0)
/* WORDS */
static unsigned long kallsyms_lookup_name(const char* name) {
  if (!strcmp(name, "genlmsg_put")) return (unsigned long)genlmsg_put_words;
  if (!strcmp(name, "genlmsg_multicast_allns")) return (unsigned long)genlmsg_multicast_allns_words;
  return 0;
}
static unsigned long kallsyms_lookup_name_by_suffix(const char* name) {
  if (!strcmp(name, "genl_pernet_exit")) return (unsigned long)genl_pernet_exit_words;
  return kallsyms_lookup_name(name);
}
#define lookup_name(n) n = (typeof(n))kallsyms_lookup_name(#n); if (!n) return -21
/* PRODUCTION */
static void reset(void) { memset(&struct_offset, 0, sizeof(struct_offset)); }
int main(void) {
  reset();
  int rc = calculate_offsets();
  printf("target rc=%d id=%d config=%d groups=%d count=%d width=%d group_offset=%d socket=%d\n", rc,
         struct_offset.genl_family_id, struct_offset.genl_family_config, struct_offset.genl_family_mcgrps,
         struct_offset.genl_family_n_mcgrps, struct_offset.genl_family_n_mcgrps_size,
         struct_offset.genl_family_mcgrp_offset, struct_offset.net_genl_sock);
  fflush(stdout); assert(rc == 0);
  assert(struct_offset.genl_family_id == 0 && struct_offset.genl_family_config == 4);
  assert(struct_offset.genl_family_mcgrps == 0x58 && struct_offset.genl_family_n_mcgrps == 0x64);
  assert(struct_offset.genl_family_n_mcgrps_size == 4 && struct_offset.genl_family_mcgrp_offset == 0x68);
  assert(struct_offset.net_genl_sock == 0x108);
  uint32_t saved = genlmsg_put_words[8];
  genlmsg_put_words[8] = 0xd503201f; reset(); assert(calculate_offsets() < 0);
  genlmsg_put_words[8] = saved | 0x80000000u; reset(); assert(calculate_offsets() < 0); // 64位 LDP 不代表两个 u32。
  genlmsg_put_words[8] = saved;
  saved = genlmsg_put_words[24];
  genlmsg_put_words[24] = 0x1100211b; reset(); assert(calculate_offsets() < 0); // hdrsize + 8 不符合头长度。
  genlmsg_put_words[24] = saved;
  saved = genlmsg_multicast_allns_words[10];
  genlmsg_multicast_allns_words[10] = 0xaa0103f7; reset(); assert(calculate_offsets() < 0); // x23 来自其它参数。
  genlmsg_multicast_allns_words[10] = saved;
  saved = genl_pernet_exit_words[5];
  genl_pernet_exit_words[5] = 0xb4000089; reset(); assert(calculate_offsets() < 0); // 空值检查不是读取的寄存器。
  genl_pernet_exit_words[5] = saved;
  puts("PASS: target Genl layout, missing/wrong-width pair, unrelated base, mismatched socket guard");
}
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    root = Path(__file__).resolve().parents[2]
    # 既有 helper 提取共同定义、偏移表和整个生产 Genl 段，不改原 Oracle。
    production = offset_source(root / 're_kernel_x').replace('#endif /* !CONFIG_KPM_BASELINES */', '')
    arrays = '\n'.join('static uint32_t ' + name + '_words[] = {' + ','.join('0x' + x for x in words.split()) + '};'
                       for name, words in WORDS.items())
    code = HOST.replace('/* WORDS */', arrays).replace('/* PRODUCTION */', instruction_source(root) + production)
    path, binary = args.output / 'genl.c', args.output / 'genl'
    path.write_text(code)
    build = subprocess.run(['clang', '-Wall', '-Werror', '-Wno-unused-function', '-fsanitize=address,undefined', str(path), '-o', str(binary)], capture_output=True, text=True)
    (args.output / 'build.log').write_text(build.stdout + build.stderr)
    assert build.returncode == 0, build.stderr
    run = subprocess.run([str(binary.resolve())], capture_output=True, text=True)
    (args.output / 'run.log').write_text(run.stdout + run.stderr)
    assert run.returncode == 0, run.stdout + run.stderr
    print(run.stdout.strip())


if __name__ == '__main__':
    main()
