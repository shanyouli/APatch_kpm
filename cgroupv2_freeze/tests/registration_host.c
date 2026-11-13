/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 执行生产注册代码的隔离宿主夹具；没有真实内核/设备/文件系统调用。 */
#define main offsets_fixture_main
#include "target_offsets_host.c"
#undef main
#include <linux/fs.h>

#define GLOBAL_SYSTEM_UID KUIDT_INIT(1000)
#define GLOBAL_SYSTEM_GID KGIDT_INIT(1000)

static struct cftype cgroup_freeze_files[] = {{.name = "cgroup.freeze", .flags = CFTYPE_NOT_ON_ROOT}, {}};
static union {
  unsigned long alignment;
  unsigned char bytes[512];
} groups[4], initial_cset;
static struct kernfs_node directories[4], files[4];
static bool present[4], lock_held;
static int create_calls, remove_calls, activate_calls, fail_create, fail_owner, owner_calls;
static struct mutex mutex_object;

/* 返回 cgrp 的夹具索引；未知对象返回 -1，不是运行时对象识别算法。 */
static int group_index(struct cgroup* cgrp) {
  for (int i = 0; i < 4; i++)
    if ((void*)cgrp == (void*)groups[i].bytes)
      return i;
  return -1;
}

/* 模拟在 cgroup_mutex 下按序遍历；pos/root 是生产算法传入的 CSS 指针。 */
static struct cgroup_subsys_state* mock_next(struct cgroup_subsys_state* pos, struct cgroup_subsys_state* root) {
  if (!lock_held || root != (void*)groups[0].bytes)
    return NULL;
  if (!pos)
    return (void*)groups[0].bytes;
  int index = group_index((void*)pos);
  return index >= 0 && index < 3 ? (void*)groups[index + 1].bytes : NULL;
}
static struct cgroup_subsys_state* (*css_next_descendant_pre)(struct cgroup_subsys_state*,
                                                            struct cgroup_subsys_state*) = mock_next;

/* 模拟原生 cftype 创建/删除；验证持锁与类型身份，支持第 N 次创建失败。 */
static int mock_addrm(struct cgroup_subsys_state* css, struct cgroup* cgrp, struct cftype* cfts, bool add) {
  int index = group_index(cgrp);
  if (!lock_held || index < 0 || (void*)css != (void*)cgrp || cfts != cgroup_freeze_files)
    return -EINVAL;
  if (index == 0)
    return 0;
  if (add) {
    create_calls++;
    if (fail_create && create_calls == fail_create)
      return -ENOMEM;
    if (present[index])
      return -EEXIST;
    present[index] = true;
  } else {
    remove_calls++;
    present[index] = false;
  }
  return 0;
}
static int (*cgroup_addrm_files)(struct cgroup_subsys_state*, struct cgroup*, struct cftype*, bool) = mock_addrm;

/* 模拟属主设置；验证引用的文件与 UID/GID，指定场景返回权限错误。 */
static ssize_t mock_setattr(struct kernfs_node* kn, const struct iattr* attr) {
  owner_calls++;
  if (!lock_held || !kn || attr->ia_uid.val != 1000 || attr->ia_gid.val != 1000)
    return -EINVAL;
  return fail_owner ? -EACCES : 0;
}
static ssize_t (*kernfs_setattr)(struct kernfs_node*, const struct iattr*) = mock_setattr;

#include "../cfv2_registration.c"

/* 模拟注册主锁；参数必须为夹具 mutex，无返回值。 */
static void mock_lock(struct mutex* lock) { lock_held = lock == &mutex_object; }
/* 模拟解锁，参数保留，无返回值。 */
static void mock_unlock(struct mutex* lock) { (void)lock; lock_held = false; }
/* 只查夹具中的 freeze 文件；不会查询宿主文件系统。 */
static struct kernfs_node* mock_find(struct kernfs_node* parent, const char* name, const void* ns) {
  if (!lock_held || ns || strcmp(name, "cgroup.freeze"))
    return NULL;
  for (int i = 0; i < 4; i++)
    if (parent == &directories[i] && present[i])
      return &files[i];
  return NULL;
}
/* 引用释放占位；kn 来自夹具，无实际内存释放。 */
static void mock_put(struct kernfs_node* kn) { (void)kn; }
/* 记录目录激活；kn 必须是根目录且锁仍持有。 */
static void mock_activate(struct kernfs_node* kn) {
  if (lock_held && kn == &directories[0])
    activate_calls++;
}

/* 重建四个夹具 cgroup；offline 指定一个不在线的对象，-1 表示全部在线。
 * 使用目标已核对的字段偏移布置测试对象；不修改生产结构或运行时算法。
 */
static void reset_fixture(int offline) {
  memset(groups, 0, sizeof(groups));
  memset(&initial_cset, 0, sizeof(initial_cset));
  memset(present, 0, sizeof(present));
  create_calls = remove_calls = activate_calls = owner_calls = 0;
  fail_create = fail_owner = 0;
  cfv2_files_registered = false;
  lock_held = false;
  struct_offset.cgroup_kn = 232;
  struct_offset.css_flags = 108;
  struct_offset.css_set_dfl_cgrp = 72;
  for (int i = 0; i < 4; i++) {
    struct cgroup* cgrp = (void*)groups[i].bytes;
    cgrp->self.cgroup = cgrp;
    *(unsigned int*)(groups[i].bytes + 108) = i == offline ? 0 : 2;
    *(struct kernfs_node**)(groups[i].bytes + 232) = &directories[i];
  }
  cfv2_init_css_set = (void*)initial_cset.bytes;
  *(struct cgroup**)(initial_cset.bytes + 72) = (void*)groups[0].bytes;
  cfv2_cgroup_mutex = &mutex_object;
  kf_mutex_lock = mock_lock;
  kf_mutex_unlock = mock_unlock;
  kf_kernfs_find_and_get_ns = mock_find;
  kf_kernfs_put = mock_put;
  kf_kernfs_activate = mock_activate;
}

/* 无参数；验证回填、冲突、回滚、离线跳过及新建目录回调，返回失败数。 */
int main(void) {
  int failures = 0;
  reset_fixture(-1);
  long rc = cfv2_register_existing_groups();
  failures += rc || !cfv2_files_registered || create_calls != 3 || owner_calls != 3 || activate_calls != 1
      || !present[1] || !present[2] || !present[3] || present[0] || lock_held;

  reset_fixture(-1);
  present[2] = true;
  rc = cfv2_register_existing_groups();
  failures += rc != -EEXIST || cfv2_files_registered || create_calls || remove_calls || !present[2]
      || present[1] || present[3] || lock_held;

  reset_fixture(-1);
  fail_create = 2;
  rc = cfv2_register_existing_groups();
  failures += rc != -ENOMEM || cfv2_files_registered || activate_calls || present[1] || present[2] || present[3]
      || lock_held;

  reset_fixture(-1);
  fail_owner = 1;
  rc = cfv2_register_existing_groups();
  failures += rc != -EACCES || cfv2_files_registered || activate_calls || present[1] || present[2] || present[3]
      || lock_held;

  reset_fixture(2);
  rc = cfv2_register_existing_groups();
  failures += rc || !cfv2_files_registered || create_calls != 2 || !present[1] || present[2] || !present[3]
      || lock_held;
  struct cftype base_files[] = {{.name = "cgroup.procs"}, {}};
  cfv2_base_files = base_files;
  lock_held = true;
  present[3] = false;
  create_calls = 0;
  hook_fargs4_t future = {.arg0 = (uint64_t)groups[3].bytes, .arg1 = (uint64_t)groups[3].bytes,
                         .arg2 = (uint64_t)base_files, .arg3 = 1, .ret = 0};
  cgroup_addrm_files_after(&future, NULL);
  failures += future.ret || !present[3] || create_calls != 1 || !lock_held;

  present[3] = false;
  create_calls = 0;
  future.arg2 = (uint64_t)cgroup_freeze_files;
  cgroup_addrm_files_after(&future, NULL);
  failures += future.ret || present[3] || create_calls;

  future.arg2 = (uint64_t)base_files;
  fail_create = 1;
  cgroup_addrm_files_after(&future, NULL);
  failures += (long)future.ret != -ENOMEM || present[3] || create_calls != 1;

  fail_create = 0;
  create_calls = 0;
  future.ret = (uint64_t)-EINVAL;
  cgroup_addrm_files_after(&future, NULL);
  failures += (long)future.ret != -EINVAL || present[3] || create_calls;
  lock_held = false;
  printf("registration fixtures: 9 scenarios, failures=%d\n", failures);
  return failures ? 1 : 0;
}
