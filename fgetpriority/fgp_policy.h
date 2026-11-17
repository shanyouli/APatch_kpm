/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2026 \xx — 条件逻辑移植自 fgetpriority/kernel/routine.h。 */
#ifndef FGP_POLICY_H
#define FGP_POLICY_H

/* 对 CONFIG_USER_NS=n 目标按原顺序比较真实 UID；返回非零表示隐藏查询。 */
static inline int fgp_filter(unsigned int caller, int who, int seccomp) {
  if (!seccomp || caller < 10000 || who < 10000)
    return 0;
  if (caller >= 100000)
    caller %= 100000;
  if (who >= 100000)
    who %= 100000;
  return caller != (unsigned int)who;
}
#endif
