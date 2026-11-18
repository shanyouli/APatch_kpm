/* SPDX-License-Identifier: GPL-2.0-only */
/* 用目标原始字节驱动生产 init/exit；不模拟内核 hook 执行或 grace period。 */
#include <assert.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include "fixtures/target_bytes.h"
#include "../fgetpriority.c"

static unsigned int uid = 10001;
static long seccomp_mode = 2;
static int hook_error, missing_symbol, unreadable, corrupt_target;
static int hook_live, corrupt_install;
static const uintptr_t chain_address = 0xffffff936b900000UL;
static const uintptr_t transit_address = 0xffffff936b900280UL;
static int wraps, removes, tasks_waits, sched_waits, frees;
static int order, detach_order, tasks_order, sched_order;
static void* freed;
static char last_log[512];
static uintptr_t frame_start, frame_end;
static const uintptr_t kernel_base = 0xffffff916b480000UL;

/* 输入为生产 nofault 地址；映射到不可变的目标字节，返回 0 或 -EFAULT。 */
static long fake_read(void* dst, const void* src, unsigned long size) {
  const uintptr_t address = (uintptr_t)src;
  volatile uintptr_t anchor = (uintptr_t)(void*)hotpatch;
  struct region { uintptr_t address; const unsigned char* bytes; size_t size; } regions[] = {
    {anchor + 0x15e10, fixture_loader, sizeof(fixture_loader)},
    {anchor - 0x3560, fixture_transit, sizeof(fixture_transit)},
    {(uintptr_t)(void*)hook_wrap, fixture_wrap, sizeof(fixture_wrap)},
    {(uintptr_t)(void*)hook_unwrap_remove, fixture_unwrap, sizeof(fixture_unwrap)},
    {kernel_base + 0x1bc494, fixture_getpriority, sizeof(fixture_getpriority)},
    {kernel_base + 0x1bc174, fixture_setpriority, sizeof(fixture_setpriority)},
    {kernel_base + 0x643e10, fixture_ioprio_get, sizeof(fixture_ioprio_get)},
    {kernel_base + 0x643b98, fixture_ioprio_set, sizeof(fixture_ioprio_set)},
  };
  if (unreadable)
    return -EFAULT;
  if (hook_live && address == kernel_base + 0x1b1bf4 && size == 16) {
    struct { uint32_t load, branch; uint64_t destination; } entry = {
      corrupt_install ? 0U : 0x58000051U, 0xd61f0220U, transit_address
    };
    memcpy(dst, &entry, size);
    return 0;
  }
  if (hook_live && address == transit_address && size == 24) {
    struct { uint32_t bti, load, branch, nop; uint64_t chain; } transit = {
      0xd50324dfU, 0x58000070U, 0x14000004U, 0xd503201fU, chain_address
    };
    memcpy(dst, &transit, size);
    return 0;
  }
  if (hook_live && address >= transit_address + 24 &&
      address - transit_address - 24 < sizeof(fixture_transit) && size == 1) {
    memcpy(dst, fixture_transit + (address - transit_address - 24), size);
    return 0;
  }
  for (size_t i = 0; i < sizeof(regions) / sizeof(regions[0]); i++) {
    struct region* r = &regions[i];
    if (address >= r->address && address - r->address < r->size && size <= r->size - (address - r->address)) {
      memcpy(dst, r->bytes + address - r->address, size);
      if (corrupt_target && address == kernel_base + 0x1bc494)
        *(unsigned char*)dst ^= 1;
      return 0;
    }
  }
  if (address >= frame_start && address < frame_end && size <= frame_end - address) {
    memcpy(dst, src, size);
    return 0;
  }
  return -EFAULT;
}

/* 记录本模块对用户引用的配平参数；不模拟实际内核引用计数。 */
static void fake_free(void* user) { frees++; freed = user; }
static long fake_seccomp(void) { return seccomp_mode; }
static void fake_tasks(void) { tasks_waits++; tasks_order = ++order; }
static void fake_sched(void) { sched_waits++; sched_order = ++order; }
unsigned int current_uid(void) { return uid; }
int hotpatch(void* addresses[], uint32_t words[], int count) {
  (void)addresses; (void)words; (void)count;
  assert(!"模块不得自行写入调用点或恢复 KP 跳板");
  return -EFAULT;
}
int printk(const char* fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  int ret = vsnprintf(last_log, sizeof(last_log), fmt, ap);
  va_end(ap);
  return ret;
}
uintptr_t kallsyms_lookup_name(const char* name) {
  if (missing_symbol && !strcmp(name, "synchronize_rcu_tasks"))
    return 0;
  if (!strcmp(name, "find_user")) return kernel_base + 0x1b1bf4;
  if (!strcmp(name, "free_uid")) return (uintptr_t)fake_free;
  if (!strcmp(name, "prctl_get_seccomp")) return (uintptr_t)fake_seccomp;
  if (!strcmp(name, "synchronize_rcu_tasks")) return (uintptr_t)fake_tasks;
  if (!strcmp(name, "synchronize_sched") || !strcmp(name, "synchronize_rcu")) return (uintptr_t)fake_sched;
  if (!strcmp(name, "probe_kernel_read")) return (uintptr_t)fake_read;
  if (!strcmp(name, "sys_getpriority")) return kernel_base + 0x1bc494;
  if (!strcmp(name, "sys_setpriority")) return kernel_base + 0x1bc174;
  if (!strcmp(name, "sys_ioprio_get")) return kernel_base + 0x643e10;
  if (!strcmp(name, "sys_ioprio_set")) return kernel_base + 0x643b98;
  return 0;
}
int __attribute__((aligned(4096))) hook_wrap(void* target, int32_t argno, void* before, void* after, void* data) {
  assert((uintptr_t)target == kernel_base + 0x1b1bf4);
  assert(argno == 1 && before == NULL && after != NULL && data == NULL);
  wraps++;
  hook_live = !hook_error;
  return hook_error;
}
void __attribute__((aligned(4096))) hook_unwrap_remove(void* target, void* before, void* after, int remove) {
  assert((uintptr_t)target == kernel_base + 0x1b1bf4);
  assert(before == NULL && after != NULL && remove == 0);
  removes++;
  detach_order = ++order;
}

/* 成功初始化必须安装原生 hook，不得因目标到 KPM 的远距离返回 ERANGE。 */
int main(void) {
  int init_result = fgp_init(NULL, "load-file", NULL);
  printf("init_result=%d log=%s\n", init_result, last_log);
  fflush(stdout);
  assert(init_result == 0);
  assert(wraps == 1);
  assert(strstr(last_log, "active") != NULL);
  struct frame {
    uintptr_t fp, lr;
    unsigned char pad[0x38];
    hook_fargs1_t args;
  } frame = {0};
  assert((uintptr_t)&frame.args - (uintptr_t)&frame == 0x48);
  frame_start = (uintptr_t)&frame;
  frame_end = frame_start + sizeof(frame);
  for (unsigned int i = 0; i < 4; i++) {
    frame.lr = allowed_callers[i];
    frame.args.arg0 = 10002;
    frame.args.ret = 0x123400;
    uintptr_t observed_caller = 0;
    assert(fake_read(&observed_caller, (char*)&frame.args - 0x40, sizeof(observed_caller)) == 0);
    assert(observed_caller == allowed_callers[i]);
    after_find_user(&frame.args, NULL);
    assert(frame.args.ret == 0 && frees == (int)i + 1 && freed == (void*)0x123400);
  }
  frame.lr = allowed_callers[0] + 4;
  frame.args.ret = 0x123400;
  after_find_user(&frame.args, NULL);
  assert(frame.args.ret == 0x123400 && frees == 4);
  frame.lr = allowed_callers[0];
  frame.args.arg0 = 110001;
  after_find_user(&frame.args, NULL);
  assert(frame.args.ret == 0x123400 && frees == 4);
  frame.args.arg0 = 10002;
  uid = 0;
  after_find_user(&frame.args, NULL);
  assert(frame.args.ret == 0x123400 && frees == 4);
  uid = 10001;
  seccomp_mode = 0;
  after_find_user(&frame.args, NULL);
  assert(frame.args.ret == 0x123400 && frees == 4);
  seccomp_mode = 2;
  frame.args.ret = 0;
  after_find_user(&frame.args, NULL);
  assert(frame.args.ret == 0 && frees == 5 && freed == NULL);
  unreadable = 1;
  frame.args.ret = 0x123400;
  after_find_user(&frame.args, NULL);
  assert(frame.args.ret == 0x123400 && frees == 5);
  unreadable = 0;
  assert(fgp_exit(NULL) == 0);
  assert(removes == 1 && tasks_waits == 1 && sched_waits == 1);
  assert(detach_order < tasks_order && tasks_order < sched_order);
  assert(fgp_exit(NULL) == 0);
  assert(removes == 1 && tasks_waits == 1 && sched_waits == 1);

  hook_error = -4093;
  assert(fgp_init(NULL, "load-file", NULL) < 0);
  assert(wraps == 2 && removes == 1);
  hook_error = 0;
  missing_symbol = 1;
  assert(fgp_init(NULL, "load-file", NULL) == -ENOENT);
  assert(wraps == 2);
  missing_symbol = 0;
  corrupt_target = 1;
  assert(fgp_init(NULL, "load-file", NULL) == -ENOEXEC);
  assert(wraps == 2);
  corrupt_target = 0;
  unreadable = 1;
  assert(fgp_init(NULL, "load-file", NULL) == -EFAULT);
  assert(wraps == 2);
  unreadable = 0;
  corrupt_install = 1;
  assert(fgp_init(NULL, "load-file", NULL) == -EIO);
  assert(wraps == 3 && removes == 2 && tasks_waits == 2 && sched_waits == 2);
  assert(active == 0 && installed == 0);
  assert(fgp_exit(NULL) == 0);
  assert(removes == 2 && tasks_waits == 2 && sched_waits == 2);
  puts("init/exit and far-address regression: passed");
  return 0;
}
