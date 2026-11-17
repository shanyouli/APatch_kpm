/* SPDX-License-Identifier: GPL-2.0-only */
#include <assert.h>
#include "../fgp_policy.h"

/* 验证原包在 CONFIG_USER_NS=n 目标上的 UID 与 seccomp 条件。 */
int main(void) {
  assert(!fgp_filter(10001, 10002, 0));
  assert(!fgp_filter(9999, 10002, 1));
  assert(!fgp_filter(10001, 9999, 1));
  assert(!fgp_filter(10001, 10001, 1));
  assert(fgp_filter(10001, 10002, 1));
  assert(!fgp_filter(110001, 10001, 1));
  assert(!fgp_filter(10001, 110001, 1));
  assert(!fgp_filter(190001, 90001, 1));
  assert(fgp_filter(90001, 10001, 1));
  assert(!fgp_filter(10001, -1, 1));
  assert(fgp_filter(100000, 10001, 1));
  return 0;
}
