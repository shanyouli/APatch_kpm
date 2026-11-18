/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2026 \xx. 保留 fgetpriority 的查找、UID 判定和引用配平语义。 */
#include <kpmodule.h>
#include <kputils.h>
#include <ksyms.h>
#include <hotpatch.h>
#include <hook.h>
#include <linux/printk.h>
#include <linux/errno.h>
#include "fgp_policy.h"
#include "fgp_scope.h"

KPM_NAME("fgetpriority");
KPM_VERSION("0.2.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("xx; KPM port");
KPM_DESCRIPTION("Target-bound priority UID filtering with KP function hook");

struct fgp_site {
  const char* name;
  unsigned int size, call_offset;
  unsigned long long fingerprint;
  void* address;
};
#include "fgp_target.h"

static void* find_user_address;
static void (*original_free_uid)(void*);
static long (*get_seccomp)(void);
static void (*wait_tasks)(void);
static void (*wait_sched)(void);
static long (*read_nofault)(void*, const void*, unsigned long);
static uintptr_t allowed_callers[4];
static unsigned int active;
static int installed;

/* nofault 读取 size 字节并计算指纹；读取失败保留 EFAULT，不修改目标代码。 */
static int code_hash(const void* address, unsigned int size, unsigned long long* result) {
  unsigned long long hash = 14695981039346656037ULL;
  for (unsigned int i = 0; i < size; i++) {
    unsigned char byte;
    if (read_nofault(&byte, (const char*)address + i, 1))
      return -EFAULT;
    hash = (hash ^ byte) * 1099511628211ULL;
  }
  *result = hash;
  return 0;
}

/* 校验指定目标的代码契约；日志标明失败阶段，避免把所有 init 错误混成同一类。 */
static int check_code(const char* stage, const void* address, unsigned int size,
                      unsigned long long expected) {
  unsigned long long observed = 0;
  int error = code_hash(address, size, &observed);
  if (error || observed != expected) {
    pr_err("fgetpriority: stage=%s rc=%d expected=%llx observed=%llx\n", stage,
           error ? error : -ENOEXEC, expected, observed);
    return error ? error : -ENOEXEC;
  }
  return 0;
}

/* KP _transit4 的已验证帧中，保存 LR 位于 fargs 前 0x40 字节；不是 task 布局偏移。 */
static void after_find_user(hook_fargs1_t* args, void* data) {
  (void)data;
  if (!__atomic_load_n(&active, __ATOMIC_ACQUIRE))
    return;
  uintptr_t caller;
  if ((uintptr_t)args < FGP_TRANSIT_SAVED_LR_BACK ||
      read_nofault(&caller, (const char*)args - FGP_TRANSIT_SAVED_LR_BACK, sizeof(caller)))
    return;
  if (fgp_caller_index(caller, allowed_callers, 4) < 0)
    return;
  if (!fgp_filter(current_uid(), (int)args->arg0, get_seccomp() != 0))
    return;
  /* 目标 free_uid 入口有空指针检查；原查找已运行，回收其引用后仅替换结果。 */
  original_free_uid((void*)(uintptr_t)args->ret);
  args->ret = 0;
}

/* 先核验加载器和 KP 帧契约，再取得四个原 BL 的返回地址；不生成远跳指令。 */
static int prepare_sites(void) {
  int error = check_code("loader", (const char*)hotpatch + FGP_LOADER_DELTA,
                         FGP_LOADER_SIZE, FGP_LOADER_HASH);
  if (error)
    return error;
  error = check_code("transit4", (const char*)hotpatch + FGP_TRANSIT4_DELTA,
                     FGP_TRANSIT4_SIZE, FGP_TRANSIT4_HASH);
  if (error)
    return error;
  error = check_code("hook_wrap", (void*)hook_wrap, FGP_WRAP_SIZE, FGP_WRAP_HASH);
  if (error)
    return error;
  error = check_code("hook_detach", (void*)hook_unwrap_remove, FGP_UNWRAP_SIZE, FGP_UNWRAP_HASH);
  if (error)
    return error;
  for (unsigned int i = 0; i < 4; i++) {
    struct fgp_site* site = &sites[i];
    site->address = (void*)kallsyms_lookup_name(site->name);
    if (!site->address) {
      pr_err("fgetpriority: stage=%s rc=%d symbol missing\n", site->name, -ENOENT);
      return -ENOENT;
    }
    error = check_code(site->name, site->address, site->size, site->fingerprint);
    if (error)
      return error;
    uintptr_t callsite = (uintptr_t)site->address + site->call_offset;
    unsigned int instruction;
    if (read_nofault(&instruction, (void*)callsite, sizeof(instruction)))
      return -EFAULT;
    if ((instruction & 0xfc000000U) != 0x94000000U)
      return -ENOEXEC;
    long words = instruction & 0x03ffffffU;
    if (words & 0x02000000L)
      words -= 0x04000000L;
    if (callsite + words * 4 != (uintptr_t)find_user_address)
      return -ENOEXEC;
    allowed_callers[i] = callsite + 4;
  }
  return 0;
}

/* 撤销本模块回调，但不释放 KP 跳板；等待不睡眠回调的任务/中断在途执行结束。 */
static void detach_and_drain(void) {
  __atomic_store_n(&active, 0, __ATOMIC_RELEASE);
  if (!installed)
    return;
  hook_unwrap_remove(find_user_address, NULL, after_find_user, 0);
  wait_tasks();
  wait_sched();
  installed = 0;
}

/* 核验原生 hook 的完整入口与复制 transit；不得仅凭 hook_wrap 返回 0 宣告启用。 */
static int verify_installed_hook(void) {
  struct { uint32_t load, branch; uint64_t destination; } entry;
  if (read_nofault(&entry, find_user_address, sizeof(entry)))
    return -EFAULT;
  if (entry.load != 0x58000051U || entry.branch != 0xd61f0220U ||
      !entry.destination || (entry.destination & 7))
    return -EIO;
  struct { uint32_t bti, load, branch, nop; uint64_t chain; } transit;
  if (read_nofault(&transit, (void*)(uintptr_t)entry.destination, sizeof(transit)))
    return -EFAULT;
  if (transit.bti != 0xd50324dfU || transit.load != 0x58000070U ||
      transit.branch != 0x14000004U || transit.nop != 0xd503201fU ||
      transit.chain != entry.destination - FGP_CHAIN_TRANSIT_OFFSET)
    return -EIO;
  return check_code("installed_transit", (void*)(uintptr_t)(entry.destination + sizeof(transit)),
                    FGP_TRANSIT4_SIZE, FGP_TRANSIT4_HASH);
}

/* 校验完整依赖后注册一个原生绝对跳转 hook；全部成功才开启过滤并返回 0。 */
static long fgp_init(const char* args, const char* event, void* reserved) {
  (void)args;
  (void)event;
  (void)reserved;
  find_user_address = (void*)kallsyms_lookup_name("find_user");
  original_free_uid = (void*)kallsyms_lookup_name("free_uid");
  get_seccomp = (void*)kallsyms_lookup_name("prctl_get_seccomp");
  wait_tasks = (void*)kallsyms_lookup_name("synchronize_rcu_tasks");
  wait_sched = (void*)kallsyms_lookup_name("synchronize_sched");
  read_nofault = (void*)kallsyms_lookup_name("copy_from_kernel_nofault");
  if (!read_nofault)
    read_nofault = (void*)kallsyms_lookup_name("probe_kernel_read");
  if (!find_user_address || !original_free_uid || !get_seccomp || !wait_tasks || !wait_sched || !read_nofault) {
    pr_err("fgetpriority: stage=resolve rc=%d find=%d free=%d seccomp=%d tasks=%d sched=%d read=%d\n",
           -ENOENT, !!find_user_address, !!original_free_uid, !!get_seccomp, !!wait_tasks, !!wait_sched,
           !!read_nofault);
    return -ENOENT;
  }
  int error = prepare_sites();
  if (error)
    return error;
  error = hook_wrap(find_user_address, 1, NULL, after_find_user, NULL);
  if (error) {
    pr_err("fgetpriority: stage=hook_wrap rc=%d\n", error);
    return error < 0 ? error : -EIO;
  }
  installed = 1;
  error = verify_installed_hook();
  if (error) {
    pr_err("fgetpriority: stage=verify_hook rc=%d\n", error);
    detach_and_drain();
    return error;
  }
  __atomic_store_n(&active, 1, __ATOMIC_RELEASE);
  pr_info("fgetpriority: active version=0.2.0 sites=4 hook=absolute scope=caller\n");
  return 0;
}

/* 目标加载器在 exit 前释放读锁；幂等清理不执行原生 unsafe 跳板释放。 */
static long fgp_exit(void* reserved) {
  (void)reserved;
  detach_and_drain();
  return 0;
}

KPM_INIT(fgp_init);
KPM_EXIT(fgp_exit);
