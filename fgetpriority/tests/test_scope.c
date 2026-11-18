/* SPDX-License-Identifier: GPL-2.0-only */
#include <assert.h>
#include <stdint.h>
#include "../fgp_scope.h"

/* 四个目标返回地址才具有过滤作用域；任务/嵌套/中断的其他调用者不命中。 */
int main(void) {
  const uintptr_t callers[] = {0xffffff916b63c544UL, 0xffffff916b63c220UL,
                               0xffffff916bac3e78UL, 0xffffff916bac3c48UL};
  for (unsigned int i = 0; i < 4; i++) {
    assert(fgp_caller_index(callers[i], callers, 4) == (int)i);
    assert(fgp_caller_index(callers[i] - 4, callers, 4) == -1);
  }
  assert(fgp_caller_index(0xffffff936b1dcee8UL, callers, 4) == -1);
  assert(fgp_caller_index(0, callers, 4) == -1);
  assert(fgp_caller_index(callers[0], callers, 0) == -1);
  return 0;
}
