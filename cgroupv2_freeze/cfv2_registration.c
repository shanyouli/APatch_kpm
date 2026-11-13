/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 真实 cgroup.freeze 文件注册；包含在业务 C 中，共用已核对的布局与回调。 */

static struct mutex* cfv2_cgroup_mutex;
static struct cgroup* cfv2_root_cgroup;
static bool cfv2_files_registered;
void kfunc_def(mutex_lock)(struct mutex* lock);
void kfunc_def(mutex_unlock)(struct mutex* lock);
struct kernfs_node* kfunc_def(kernfs_find_and_get_ns)(struct kernfs_node* parent, const char* name, const void* ns);
void kfunc_def(kernfs_put)(struct kernfs_node* kn);
void kfunc_def(kernfs_activate)(struct kernfs_node* kn);

/* cgrp 为受 cgroup_mutex 保护的存活对象；返回其 kernfs 目录，不增加引用。 */
static struct kernfs_node* cfv2_cgroup_kn(struct cgroup* cgrp) {
  return *(struct kernfs_node**)((uintptr_t)cgrp + struct_offset.cgroup_kn);
}

/* css 为遍历期间的对象；返回 CSS_ONLINE 状态，不延长对象生命周期。 */
static bool cfv2_css_online(struct cgroup_subsys_state* css) {
  return (*(unsigned int*)((uintptr_t)css + struct_offset.css_flags) & (1U << 1)) != 0;
}

/* 解析注册所需原生依赖。无参数；返回 0 或缺项错误，尚不发布任何文件。 */
static long cfv2_resolve_registration(void) {
  cfv2_cgroup_mutex = (typeof(cfv2_cgroup_mutex))kallsyms_lookup_name_by_suffix("cgroup_mutex");
  if (!cfv2_cgroup_mutex || !cfv2_init_css_set)
    return -ENOENT;
  cfv2_kfunc_lookup_name(mutex_lock);
  cfv2_kfunc_lookup_name(mutex_unlock);
  cfv2_kfunc_lookup_name(kernfs_find_and_get_ns);
  cfv2_kfunc_lookup_name(kernfs_put);
  cfv2_kfunc_lookup_name(kernfs_activate);
  return 0;
}

/* 对一个存活 cgrp 添加/移除接口；调用者持 cgroup_mutex，is_add 控制动作。
 * 添加后设置 system:system 属主；返回原生错误，失败由调用者回滚已创建文件。
 */
static int cfv2_update_group_file(struct cgroup* cgrp, bool is_add) {
  int rc = cgroup_addrm_files(&cgrp->self, cgrp, cgroup_freeze_files, is_add);
  if (rc || !is_add || cgrp == cfv2_root_cgroup)
    return rc;
  struct kernfs_node* kn = kfunc(kernfs_find_and_get_ns)(cfv2_cgroup_kn(cgrp), "cgroup.freeze", NULL);
  if (!kn)
    return -ENOENT;
  struct iattr attr = {
      .ia_valid = ATTR_UID | ATTR_GID,
      .ia_uid = GLOBAL_SYSTEM_UID,
      .ia_gid = GLOBAL_SYSTEM_GID,
  };
  rc = kernfs_setattr(kn, &attr);
  kfunc(kernfs_put)(kn);
  return rc;
}

/* 在模块 init 的可睡眠上下文回填已有默认层级；无参数，成功返回 0。
 * 两遍遍历先排除同名文件冲突，再创建真实内核接口；任一步失败在同一把锁下
 * 回滚本轮文件。未来目录由 cgroup_addrm_files_after 接入，不重挂载、不迁移任务。
 */
static long cfv2_register_existing_groups(void) {
  int rc = 0;
  struct cgroup_subsys_state* css;
  kfunc(mutex_lock)(cfv2_cgroup_mutex);
  cfv2_root_cgroup = css_set_dfl_cgrp(cfv2_init_css_set);
  if (!cfv2_root_cgroup || cfv2_root_cgroup->self.cgroup != cfv2_root_cgroup || cfv2_root_cgroup->self.ss
      || !cfv2_cgroup_kn(cfv2_root_cgroup)) {
    rc = -EOPNOTSUPP;
    goto out;
  }

  css_for_each_descendant_pre(css, &cfv2_root_cgroup->self) {
    struct cgroup* cgrp = css->cgroup;
    if (cgrp == cfv2_root_cgroup || !cfv2_css_online(css) || !cfv2_cgroup_kn(cgrp))
      continue;
    struct kernfs_node* kn = kfunc(kernfs_find_and_get_ns)(cfv2_cgroup_kn(cgrp), "cgroup.freeze", NULL);
    if (kn) {
      kfunc(kernfs_put)(kn);
      rc = -EEXIST;
      goto out;
    }
  }

  unsigned int count = 0;
  css_for_each_descendant_pre(css, &cfv2_root_cgroup->self) {
    struct cgroup* cgrp = css->cgroup;
    if (!cfv2_css_online(css) || !cfv2_cgroup_kn(cgrp))
      continue;
    rc = cfv2_update_group_file(cgrp, true);
    if (rc)
      goto rollback;
    if (cgrp != cfv2_root_cgroup)
      count++;
  }
  cfv2_files_registered = true;
  kfunc(kernfs_activate)(cfv2_cgroup_kn(cfv2_root_cgroup));
  logkm("registered cgroup.freeze in %u existing groups\n", count);
  goto out;

rollback:
  css_for_each_descendant_pre(css, &cfv2_root_cgroup->self) {
    struct cgroup* cgrp = css->cgroup;
    if (cfv2_css_online(css) && cfv2_cgroup_kn(cgrp))
      cfv2_update_group_file(cgrp, false);
  }
out:
  kfunc(mutex_unlock)(cfv2_cgroup_mutex);
  return rc;
}

/* 原生基准文件创建成功后，给同一 cgroup 添加本模块接口。args 为原生参数。
 * udata 未使用，无返回值；只处理默认层级的基准表，避免 controller 表重复
 * 触发或本模块表递归。失败写回原调用，由内核目录创建路径处理。
 * 调用上下文继承 cgroup_mutex，不在这里重新获取该锁。
 */
static void cgroup_addrm_files_after(hook_fargs4_t* args, void* udata) {
  (void)udata;
  int ret = (int)args->ret;
  if (ret || !cfv2_files_registered || (struct cftype*)args->arg2 != cfv2_base_files)
    return;
  ret = cfv2_update_group_file((struct cgroup*)args->arg1, (bool)args->arg3);
  if (ret)
    args->ret = ret;
}
