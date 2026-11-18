/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef FGP_TEST_KP_H
#define FGP_TEST_KP_H
#include <stddef.h>
#include <stdint.h>
#include <errno.h>
#define KPM_NAME(x)
#define KPM_VERSION(x)
#define KPM_LICENSE(x)
#define KPM_AUTHOR(x)
#define KPM_DESCRIPTION(x)
#define KPM_INIT(x)
#define KPM_EXIT(x)
#define pr_info(...) printk(__VA_ARGS__)
#define pr_warn(...) printk(__VA_ARGS__)
#define pr_err(...) printk(__VA_ARGS__)
typedef struct {
  void* chain;
  int skip_origin;
  struct { uint64_t data[8]; } local;
  uint64_t ret;
  uint64_t arg0, arg1, arg2, arg3;
} hook_fargs1_t;
uintptr_t kallsyms_lookup_name(const char*);
unsigned int current_uid(void);
int hotpatch(void*[], uint32_t[], int);
int printk(const char*, ...);
int hook_wrap(void*, int32_t, void*, void*, void*);
void hook_unwrap_remove(void*, void*, void*, int);
#endif
