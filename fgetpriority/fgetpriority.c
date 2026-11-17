/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2026 \xx. 移植自 fgetpriority，保留原主路径语义。 */
#include <kpmodule.h>
#include <kputils.h>
#include <ksyms.h>
#include <hotpatch.h>
#include <linux/printk.h>
#include <linux/errno.h>
#include "fgp_policy.h"

KPM_NAME("fgetpriority");
KPM_VERSION("0.1.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("xx; KPM port");
KPM_DESCRIPTION("Target-bound priority UID filtering; exploration build");

struct fgp_site {
  const char* name;
  unsigned int size, call_offset;
  unsigned long long fingerprint;
  void* address;
  void* patch;
  unsigned int original, replacement;
  int installed;
};
#include "fgp_target.h"

static void* (*original_find_user)(unsigned int);
static void (*original_free_uid)(void*);
static long (*get_seccomp)(void);
static void (*wait_rcu)(void);
static long (*read_nofault)(void*, const void*, unsigned long);

/* 读取内核代码指纹；读取失败返回错误，避免解引用无效目标地址。 */
static int code_hash(const void* address, unsigned int size, unsigned long long* result) {
  unsigned long long h = 14695981039346656037ULL;
  for (unsigned int i = 0; i < size; i++) {
    unsigned char byte;
    if (read_nofault(&byte, (const char*)address + i, 1))
      return -EFAULT;
    h = (h ^ byte) * 1099511628211ULL;
  }
  *result = h;
  return 0;
}

/* 原 syscall 已持有 RCU 读锁；先执行原查找，再按原包条件配平引用。 */
static void* filtered_find_user(unsigned int uid) {
  void* user = original_find_user(uid);
  if (fgp_filter(current_uid(), (int)uid, get_seccomp() != 0)) {
    original_free_uid(user);
    return 0;
  }
  return user;
}

/* 生成 B/BL，保留原指令类型；不截断超出正负 128 MiB 的距离。 */
static int encode_branch(unsigned long from, unsigned long to, unsigned int* result) {
  long delta = (long)to - (long)from;
  if ((delta & 3) || delta < -(1L << 27) || delta >= (1L << 27))
    return -ERANGE;
  *result = 0x94000000U | ((unsigned long)(delta / 4) & 0x03ffffffU);
  return 0;
}

/* 只检查与本次镜像相同的代码，不修改任何调用点。 */
static int prepare_sites(void) {
  unsigned long long hash;
  unsigned long loader = (unsigned long)hotpatch + FGP_LOADER_DELTA;
  if (code_hash((void*)loader, FGP_LOADER_SIZE, &hash) || hash != FGP_LOADER_HASH)
    return -ENOEXEC;
  for (unsigned int i = 0; i < sizeof(sites) / sizeof(sites[0]); i++) {
    struct fgp_site* site = &sites[i];
    site->address = (void*)kallsyms_lookup_name(site->name);
    if (!site->address || code_hash(site->address, site->size, &hash) || hash != site->fingerprint)
      return -ENOEXEC;
    site->patch = (char*)site->address + site->call_offset;
    if (read_nofault(&site->original, site->patch, sizeof(site->original)))
      return -EFAULT;
    unsigned int expected;
    if (encode_branch((unsigned long)site->patch, (unsigned long)original_find_user, &expected)
        || expected != site->original)
      return -ENOEXEC;
    int error = encode_branch((unsigned long)site->patch, (unsigned long)filtered_find_user,
                              &site->replacement);
    if (error)
      return error;
  }
  return 0;
}

/* 探索入口只做依赖和代码预检；补丁生命周期尚未审定，禁止启用。 */
static long fgp_init(const char* args, const char* event, void* reserved) {
  (void)args;
  (void)event;
  (void)reserved;
  original_find_user = (void*)kallsyms_lookup_name("find_user");
  original_free_uid = (void*)kallsyms_lookup_name("free_uid");
  get_seccomp = (void*)kallsyms_lookup_name("prctl_get_seccomp");
  wait_rcu = (void*)kallsyms_lookup_name("synchronize_rcu");
  read_nofault = (void*)kallsyms_lookup_name("copy_from_kernel_nofault");
  if (!read_nofault)
    read_nofault = (void*)kallsyms_lookup_name("probe_kernel_read");
  if (!original_find_user || !original_free_uid || !get_seccomp || !wait_rcu || !read_nofault)
    return -ENOENT;
  int error = prepare_sites();
  if (error)
    return error;
  pr_warn("fgetpriority: preflight passed; patch lifecycle not approved, refusing activation\n");
  return -EOPNOTSUPP;
}

/* init 不安装任何补丁；清理不等待、不访问失效的目标函数。 */
static long fgp_exit(void* reserved) {
  (void)reserved;
  return 0;
}

KPM_INIT(fgp_init);
KPM_EXIT(fgp_exit);
