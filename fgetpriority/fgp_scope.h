/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef FGP_SCOPE_H
#define FGP_SCOPE_H
#include <stdint.h>

/* 返回匹配的调用点索引；caller 为原函数的返回地址，未匹配返回 -1。 */
static inline int fgp_caller_index(uintptr_t caller, const uintptr_t* allowed, unsigned int count) {
  for (unsigned int i = 0; i < count; i++)
    if (caller == allowed[i])
      return (int)i;
  return -1;
}
#endif
