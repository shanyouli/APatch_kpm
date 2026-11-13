/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2024 bmax121. All Rights Reserved.
 * Copyright (C) 2024 lzghzr. All Rights Reserved.
 */
#ifndef __CF_UTILS_H
#define __CF_UTILS_H

#include <ksyms.h>
#include <linux/errno.h>

#define logkm(fmt, ...) printk("cgroupv2_freeze: " fmt, ##__VA_ARGS__)

/* 查询模块自有函数指针；func 为标识符，缺失时从初始化/推导返回 -ENOENT。
 * 使用当前 KP 的后缀查询，不硬编码厂商哈希，也不自行绕过 CFI。
 */
#define cfv2_lookup_name(func)                                                   \
  do {                                                                          \
    func = (typeof(func))kallsyms_lookup_name_by_suffix(#func);                    \
    if (!func) {                                                                \
      logkm("required symbol %s not found (check KP CFI suffix support)\n", #func); \
      return -ENOENT;                                                            \
    }                                                                           \
  } while (0)

/* 查询 SDK kfunc 指针；func 为标识符，缺失时返回 -ENOENT，禁止继续解引用。 */
#define cfv2_kfunc_lookup_name(func)                       \
  do {                                                     \
    kfunc_lookup_name(func);                                \
    if (!kfunc(func)) {                                     \
      logkm("required symbol %s not found\n", #func);        \
      return -ENOENT;                                       \
    }                                                      \
  } while (0)

/* 安装 init 的回调；参数沿用 hook_wrap，记录 func##_hooked。
 * 失败设置 init 的 rc 并跳转 fail_hooks，统一逆序撤销已成功的安装。
 */
#define cfv2_hook_func(func, argno, before, after, udata)           \
  do {                                                            \
    hook_err_t err = hook_wrap(func, argno, before, after, udata);  \
    if (err) {                                                    \
      logkm("hook %s failed: %d\n", #func, err);                  \
      rc = -23;                                                   \
      goto fail_hooks;                                            \
    }                                                             \
    func##_hooked = true;                                         \
  } while (0)

/* 仅撤销已安装的指定 before/after；无返回值，可重复清理部分初始化。 */
#define cfv2_unhook_func(func, before, after)            \
  do {                                                  \
    if (func##_hooked) {                                 \
      func##_hooked = false;                             \
      hook_unwrap(func, before, after);                  \
    }                                                   \
  } while (0)

struct struct_offset {
  int16_t cgroup_flags;
  int16_t cgroup_kn;
  int16_t css_flags;
  int16_t sighand_siglock;
  int16_t css_set_dfl_cgrp;
  int16_t freezer_state;
  int16_t seq_file_private;
  int16_t signal_struct_flags;
  int16_t signal_struct_group_exit_task;
  int16_t subprocess_info_argv;
  int16_t subprocess_info_path;
  int16_t task_struct_css_set;
  int16_t task_struct_flags;
  int16_t task_struct_jobctl;
  int16_t task_struct_signal;
  int16_t task_struct_state;
};

#endif /* __CF_UTILS_H */
