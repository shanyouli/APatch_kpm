/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2024 bmax121. All Rights Reserved.
 * Copyright (C) 2024 lzghzr. All Rights Reserved.
 */

#include "cgroupv2_freeze.h"

#include <compiler.h>
#include <kpmodule.h>
#include <kputils.h>
#include <linux/err.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <linux/umh.h>

#include "../kpm_utils.h"
#include "cfv2_utils.h"
#include "cfv2_setup.h"

KPM_NAME("cgroupv2_freeze");
KPM_VERSION(MYKPM_VERSION);
KPM_LICENSE("GPL v2");
KPM_AUTHOR("lzghzr");
KPM_DESCRIPTION("add cgroup.freeze with native cgroup registration");

#define GLOBAL_SYSTEM_UID KUIDT_INIT(1000)
#define GLOBAL_SYSTEM_GID KGIDT_INIT(1000)

// IZERO 表示已识别新形态；UZERO 是既有旧形态分支，不作为偏移值使用。
#define IZERO (1UL << 0x10)
#define UZERO (1UL << 0x20)

// 延迟加载, KernelPatch支持 事件加载 后弃用
static struct file* (*do_filp_open)(int dfd, struct filename* pathname, const struct open_flags* op);

// do_freezer_trap
static int (*proc_pid_wchan)(struct seq_file* m, struct pid_namespace* ns, struct pid* pid, struct task_struct* task);
void kfunc_def(schedule)(void);
// cgroup_freeze_task
static void (*signal_wake_up_state)(struct task_struct* t, unsigned int state);
struct sighand_struct;
static struct sighand_struct* (*cfv2_lock_sighand)(struct task_struct* task, unsigned long* flags);
static void (*cfv2_unlock_sighand)(raw_spinlock_t* lock, unsigned long flags);
int kfunc_def(wake_up_process)(struct task_struct* p);
// cgroup_do_freeze
static void (*css_task_iter_start)(struct cgroup_subsys_state* css, unsigned int flags, struct css_task_iter* it);
static void (*css_task_iter_start_v4)(struct cgroup_subsys_state* css, struct css_task_iter* it);
static struct task_struct* (*css_task_iter_next)(struct css_task_iter* it);
static void (*css_task_iter_end)(struct css_task_iter* it);
// cgroup_freeze
static struct cgroup_subsys_state* (*css_next_descendant_pre)(struct cgroup_subsys_state* pos,
                                                              struct cgroup_subsys_state* root);
// cgroup_freeze_show
struct cgroup_subsys_state* kfunc_def(of_css)(struct kernfs_open_file* of);
void kfunc_def(seq_printf)(struct seq_file* m, const char* f, ...);
// cgroup_freeze_write
static struct cgroup* (*cgroup_kn_lock_live)(struct kernfs_node* kn, bool drain_offline);
static struct cgroup* (*cgroup_kn_lock_live_v4)(struct kernfs_node* kn);
static void (*cgroup_kn_unlock)(struct kernfs_node* kn);
int kfunc_def(kstrtoint)(const char* s, unsigned int base, int* res);
char* kfunc_def(strim)(char* s);
// run_cmd
int kfunc_def(call_usermodehelper)(const char* path, char** argv, char** envp, int wait);
int kfunc_def(call_usermodehelper_exec)(struct subprocess_info* info, int wait);
static int* selinux_enforcing;
struct selinux_state* selinux_state;

// hook cgroup_addrm_files
static int (*cgroup_addrm_files)(struct cgroup_subsys_state* css, struct cgroup* cgrp, struct cftype cfts[],
                                 bool is_add);
static int (*cgroup_init_cftypes)(struct cgroup_subsys* ss, struct cftype* cfts);
// hook cgroup_procs_write
static ssize_t (*cgroup_procs_write)(struct kernfs_open_file* of, char* buf, size_t nbytes, loff_t off);
// hook css_set_move_task
static void (*css_set_move_task)(struct task_struct* task, struct css_set* from_cset, struct css_set* to_cset,
                                 bool use_mg_tasks);
// hook __kernfs_create_file
static ssize_t (*__kernfs_create_file)(struct kernfs_node* parent, const char* name, umode_t mode, loff_t size,
                                       const struct kernfs_ops* ops, void* priv, const void* ns,
                                       struct lock_class_key* key);
static ssize_t (*kernfs_setattr)(struct kernfs_node* kn, const struct iattr* iattr);
// hook get_signal
static bool (*get_signal)(struct ksignal* ksig);

/* init 失败也会进入 exit；只记录并撤销本模块实际安装的回调。 */
static bool get_signal_hooked, proc_pid_wchan_hooked, cgroup_addrm_files_hooked, cgroup_procs_write_hooked,
    css_set_move_task_hooked, __kernfs_create_file_hooked, do_filp_open_hooked;
static long inline_hook_exit(void* __user reserved);

struct struct_offset struct_offset = {
    .task_struct_state = -1, .css_set_dfl_cgrp = -1, .cgroup_kn = -1, .css_flags = -1, .sighand_siglock = -1};
static struct css_set* cfv2_init_css_set;
static struct cftype* cfv2_base_files;
static uint64_t css_task_iter_start_ver5 = UZERO, cgroup_kn_lock_live_ver5 = UZERO, cftype_ver5 = UZERO,
                cgroup_base_files_ver5 = UZERO;
#include "cfv2_offsets.c"

/* 设置任务冻结请求。task 为迭代器持有的任务，freeze 为目标状态；无返回值。
 * 原生 lock_task_sighand 提供任务退出保护与 siglock；jobctl 修改和唤醒都在
 * 该锁内完成。内核线程和已退出任务不处理，不用模块锁替代原生锁。
 */
static void cgroup_freeze_task(struct task_struct* task, bool freeze) {
  if (!task || (task_flags(task) & PF_KTHREAD))
    return;
  unsigned long irq_flags;
  struct sighand_struct* sighand = cfv2_lock_sighand(task, &irq_flags);
  if (!sighand)
    return;
  unsigned long* jobctl = task_jobctl_ptr(task);
  if (freeze) {
    *jobctl |= JOBCTL_TRAP_FREEZE;
    signal_wake_up_state(task, 0);
  } else {
    *jobctl &= ~JOBCTL_TRAP_FREEZE;
    kfunc(wake_up_process)(task);
  }
  cfv2_unlock_sighand((raw_spinlock_t*)((uintptr_t)sighand + struct_offset.sighand_siglock), irq_flags);
}

static void cgroup_do_freeze(struct cgroup* cgrp, bool freeze) {
  struct css_task_iter it;
  struct task_struct* task;

  unsigned long* flags = cgroup_flags_ptr(cgrp);
  if (freeze) {
    set_bit(CGRP_FREEZE, flags);
  } else {
    clear_bit(CGRP_FREEZE, flags);
  }

  if (css_task_iter_start_ver5 == IZERO) {
    css_task_iter_start(&cgrp->self, 0, &it);
  } else {
    css_task_iter_start_v4(&cgrp->self, &it);
  }
  while ((task = css_task_iter_next(&it))) {
    unsigned int flags = task_flags(task);
    if (flags & PF_KTHREAD)
      continue;
    cgroup_freeze_task(task, freeze);
  }
  css_task_iter_end(&it);
}

static void cgroup_freeze(struct cgroup* cgrp, bool freeze) {
  struct cgroup_subsys_state* css;
  struct cgroup* dsct;

  css_for_each_descendant_pre(css, &cgrp->self) {
    dsct = css->cgroup;
    cgroup_do_freeze(dsct, freeze);
  }
}

static ssize_t kernfs_node_freeze(struct kernfs_node* kn, bool freeze, bool force) {
  struct cgroup* cgrp;
  if (cgroup_kn_lock_live_ver5 == IZERO) {
    cgrp = cgroup_kn_lock_live(kn, false);
  } else {
    cgrp = cgroup_kn_lock_live_v4(kn);
  }

  if (!cgrp)
    return -ENOENT;

  if (!force) {
    unsigned long* flags = cgroup_flags_ptr(cgrp);
    freeze = test_bit(CGRP_FREEZE, flags);
  }

  cgroup_freeze(cgrp, freeze);

  cgroup_kn_unlock(kn);

  return 0;
}

static int cgroup_freeze_show(struct seq_file* seq, void* v) {
  struct kernfs_open_file* private = seq_file_private(seq);
  struct cgroup_subsys_state* css = kfunc(of_css)(private);
  struct cgroup* cgrp = css->cgroup;

  unsigned long* flags = cgroup_flags_ptr(cgrp);

  kfunc(seq_printf)(seq, "%d\n", test_bit(CGRP_FREEZE, flags));

  return 0;
}

static ssize_t cgroup_freeze_write(struct kernfs_open_file* of, char* buf, size_t nbytes, loff_t off) {
  int freeze;

  ssize_t ret = kfunc(kstrtoint)(kfunc(strim)(buf), 0, &freeze);
  if (ret)
    return ret;

  if (freeze < 0 || freeze > 1)
    return -ERANGE;

  ssize_t rc = kernfs_node_freeze(of->kn, freeze, true);
  if (rc)
    return rc;
  else
    return nbytes;
}

static struct cftype cgroup_freeze_files[] = {
    {
        .name = "cgroup.freeze",
        .flags = CFTYPE_NOT_ON_ROOT,
    },
    {},
};

#include "cfv2_registration.c"

static const char uid_[] = "uid_";
static const char uid_0[] = "uid_0";
static const char pid_[] = "pid_";
// v1 模式并不会附加到 dfl_cgrp, 需要特殊处理
static void cgroup_procs_write_after(hook_fargs4_t* args, void* udata) {
  size_t nbytes = (size_t)args->arg2;
  size_t ret = (size_t)args->ret;
  if (ret != nbytes)
    return;

  struct kernfs_open_file* of = (struct kernfs_open_file*)args->arg0;
  struct kernfs_node* kn = NULL;

  // 处理 v1 frozen 模式
  if (!strcmp(of->kn->parent->name, "frozen") || !strcmp(of->kn->parent->name, "unfrozen")) {
    kn = of->kn->parent;
  }
  // 处理 v1 uid 模式
  if (!memcmp(of->kn->parent->name, pid_, sizeof(pid_) - 1)
      && (memcmp(of->kn->parent->parent->name, uid_0, sizeof(uid_0)))
      && !memcmp(of->kn->parent->parent->name, uid_, sizeof(uid_) - 1)) {
    kn = of->kn->parent->parent;
  }
  if (!kn)
    return;

  kernfs_node_freeze(kn, false, false);
}
// 处理 v2 uid 模式
static void css_set_move_task_after(hook_fargs4_t* args, void* udata) {
  struct task_struct* task = (struct task_struct*)args->arg0;
  if (!task)
    return;

  struct css_set* from_cset = (struct css_set*)args->arg1;
  struct cgroup* from_cgrp = NULL;
  unsigned long* from_flags = NULL;

  struct css_set* to_cset = (struct css_set*)args->arg2;
  struct cgroup* to_cgrp = NULL;
  unsigned long* to_flags = NULL;

  if (from_cset) {
    from_cgrp = css_set_dfl_cgrp(from_cset);
    from_flags = cgroup_flags_ptr(from_cgrp);
  }
  if (to_cset) {
    to_cgrp = css_set_dfl_cgrp(to_cset);
    to_flags = cgroup_flags_ptr(to_cgrp);
  }

  if (!from_cset && to_cset) {
    if (test_bit(CGRP_FREEZE, to_flags))
      cgroup_freeze_task(task, true);
  } else if (from_cset && to_cset) {
    if (test_bit(CGRP_FREEZE, from_flags) != test_bit(CGRP_FREEZE, to_flags)) {
      cgroup_freeze_task(task, test_bit(CGRP_FREEZE, to_flags));
    }
  }
}
// 修改 cgroup.freeze 所有者为 system:system
static void __kernfs_create_file_after(hook_fargs8_t* args, void* udata) {
  struct kernfs_node* kn = (struct kernfs_node*)args->ret;

  if (IS_ERR(kn))
    return;

  if (!strcmp(kn->name, "cgroup.freeze")) {
    struct iattr iattr = {
        .ia_valid = ATTR_UID | ATTR_GID,
        .ia_uid = GLOBAL_SYSTEM_UID,
        .ia_gid = GLOBAL_SYSTEM_GID,
    };

    kernfs_setattr(kn, &iattr);
  }
}

static inline int signal_group_exit(struct signal_struct* sig) {
  unsigned int flags = signal_flags(sig);
  struct task_struct* group_exit_task = signal_group_exit_task(sig);
  return (flags & SIGNAL_GROUP_EXIT) || (group_exit_task != NULL);
}

/* get_signal 已处理完当前信号后执行一次冻结等待；无参数和返回值。
 * 在 siglock 下关闭入睡与信号到达之间的竞态，保留挂起信号交给原生处理。
 * 醒来仍被冻结时通过原生唤醒接口重新置 pending，让返回用户态路径再次
 * 调用 get_signal；不在模块内部绕过原生 SIGKILL/停止信号处理无限循环。
 */
static void do_freezer_trap(void) {
  unsigned long irq_flags;
  struct sighand_struct* sighand = cfv2_lock_sighand(current, &irq_flags);
  if (!sighand)
    return;
  unsigned long jobctl = task_jobctl(current);
  if ((jobctl & (JOBCTL_PENDING_MASK | JOBCTL_TRAP_FREEZE)) != JOBCTL_TRAP_FREEZE
      || signal_group_exit(task_signal(current))
      || test_bit(TIF_SIGPENDING, (unsigned long*)&current_thread_info()->flags)) {
    cfv2_unlock_sighand((raw_spinlock_t*)((uintptr_t)sighand + struct_offset.sighand_siglock), irq_flags);
    return;
  }
  *task_state_ptr(current) = TASK_INTERRUPTIBLE;
  *task_flags_ptr(current) |= PF_FREEZER_SKIP;
  cfv2_unlock_sighand((raw_spinlock_t*)((uintptr_t)sighand + struct_offset.sighand_siglock), irq_flags);
  kfunc(schedule)();
  *task_flags_ptr(current) &= ~PF_FREEZER_SKIP;

  sighand = cfv2_lock_sighand(current, &irq_flags);
  if (!sighand)
    return;
  if (task_jobctl(current) & JOBCTL_TRAP_FREEZE)
    signal_wake_up_state(current, 0);
  cfv2_unlock_sighand((raw_spinlock_t*)((uintptr_t)sighand + struct_offset.sighand_siglock), irq_flags);
}

/* args 为 get_signal 的返回现场；udata 未使用，无返回值。
 * 只有原函数没有选出信号时才等待，避免冻结逻辑遮蔽待处理的致命信号。
 */
static void get_signal_after(hook_fargs1_t* args, void* udata) {
  if (!args->ret && (task_jobctl(current) & JOBCTL_TRAP_FREEZE))
    do_freezer_trap();
}
// kpm 模块 wchan 函数名总为0, 需要手动修改
static void proc_pid_wchan_before(hook_fargs4_t* args, void* udata) {
  struct seq_file* m = (struct seq_file*)args->arg0;
  struct task_struct* task = (struct task_struct*)args->arg3;

  unsigned long jobctl = task_jobctl(task);
  // 用 lookup_symbol_name 判断一下会更好
  if (unlikely(jobctl & JOBCTL_TRAP_FREEZE)) {
    kfunc(seq_printf)(m, "%s", "do_freezer_trap");
    args->ret = 0;
    args->skip_origin = true;
  }
}

/* 临时恢复真实 UMH 路径。args 为本次 exec 参数，udata 未使用；无返回值。
 * 只在 argv[0] 有效时改写 path；调用者负责配对撤销回调。
 */
static void call_usermodehelper_exec_before(hook_fargs2_t* args, void* udata) {
  struct subprocess_info* sub_info = (struct subprocess_info*)args->arg0;
  if (!sub_info)
    return;

  char** argv = subprocess_info_argv(sub_info);
  if (!argv || !argv[0])
    return;
  *(char**)((uintptr_t)sub_info + struct_offset.subprocess_info_path) = argv[0];
}

/* 执行以 NULL 结尾的命令数组 cmd；返回首个非零 UMH/进程状态，成功返回 0。
 * 仅用于既有延迟初始化路径，可睡眠；保留旧实现临时切换 SELinux 的副作用。
 * 临时 hook 安装失败不改 SELinux；执行结束恢复状态，只撤销本模块的回调。
 */
static int run_cmd(char* cmd[]) {
  char* envp[] = {"HOME=/", "PATH=/system/bin:/system/xbin:/vendor/bin:/sbin:/bin", NULL};
  bool sel;
  int rc = 0;

  if (selinux_enforcing) {
    sel = *selinux_enforcing;
    *selinux_enforcing = false;
  } else {
    hook_err_t err = hook_wrap2(kfunc(call_usermodehelper_exec), call_usermodehelper_exec_before, NULL, NULL);
    if (err) {
      logkm("temporary UMH hook failed: %d\n", err);
      return -EINVAL;
    }
    sel = selinux_state->enforcing;
    selinux_state->enforcing = false;
  }

  for (int i = 0; cmd[i]; i++) {
    char* argv[] = {"/system/bin/sh", "-c", cmd[i], NULL};
    rc = call_usermodehelper(argv[0], argv, envp, UMH_WAIT_PROC);
    if (rc)
      break;
  }

  if (selinux_enforcing) {
    *selinux_enforcing = sel;
  } else {
    selinux_state->enforcing = sel;
    hook_unwrap(kfunc(call_usermodehelper_exec), call_usermodehelper_exec_before, NULL);
  }
  return rc;
}

static const char apm[] = "/data/adb/modules/";
/* 在第一次模块目录打开后运行初始化命令。args 为打开参数，udata 未使用。
 * 无返回值；先移除本回调避免 UMH 路径递归触发，失败只报告，不自动重试。
 */
static void do_filp_open_after(hook_fargs3_t* args, void* udata) {
  struct filename* pathname = (struct filename*)args->arg1;
  if (!pathname || !pathname->name || strncmp(pathname->name, apm, sizeof(apm) - 1))
    return;

  do_filp_open_hooked = false;
  hook_unwrap(do_filp_open, NULL, do_filp_open_after);
  char* cmd[] = {(char*)cfv2_setup_cmd, NULL};
  int rc = run_cmd(cmd);
  if (rc)
    logkm("cgroup setup failed: %d (existing groups may lack cgroup.freeze)\n", rc);
}

/* 初始化模块依赖、偏移与 hook。args/reserved 保留，event 控制既有延迟加载。
 * 成功返回 0；符号、偏移或 hook 失败返回负值，不将自检结果视为设备兼容结论。
 */
static long inline_hook_init(const char* args, const char* event, void* __user reserved) {
  // 原生 freezer 的函数也可能有编译器后缀。
  if (kallsyms_lookup_name_by_suffix("cgroup_freeze_write"))
    return -24;

  cfv2_lookup_name(do_filp_open);
  cfv2_lookup_name(proc_pid_wchan);
  cfv2_kfunc_lookup_name(schedule);

  cfv2_lookup_name(signal_wake_up_state);
  cfv2_lock_sighand = (typeof(cfv2_lock_sighand))kallsyms_lookup_name_by_suffix("__lock_task_sighand");
  cfv2_unlock_sighand = (typeof(cfv2_unlock_sighand))kallsyms_lookup_name_by_suffix("_raw_spin_unlock_irqrestore");
  if (!cfv2_lock_sighand || !cfv2_unlock_sighand)
    return -ENOENT;
  cfv2_kfunc_lookup_name(wake_up_process);

  cfv2_lookup_name(css_task_iter_start);
  css_task_iter_start_v4 = (typeof(css_task_iter_start_v4))css_task_iter_start;
  cfv2_lookup_name(css_task_iter_next);
  cfv2_lookup_name(css_task_iter_end);

  cfv2_lookup_name(css_next_descendant_pre);

  cfv2_kfunc_lookup_name(of_css);
  cfv2_kfunc_lookup_name(seq_printf);

  cfv2_lookup_name(cgroup_kn_lock_live);
  cgroup_kn_lock_live_v4 = (typeof(cgroup_kn_lock_live_v4))cgroup_kn_lock_live;
  cfv2_lookup_name(cgroup_kn_unlock);
  cfv2_kfunc_lookup_name(kstrtoint);
  cfv2_kfunc_lookup_name(strim);

  cfv2_kfunc_lookup_name(call_usermodehelper);
  cfv2_kfunc_lookup_name(call_usermodehelper_exec);

  selinux_enforcing = (typeof(selinux_enforcing))kallsyms_lookup_name_by_suffix("selinux_enforcing");
  selinux_state = (typeof(selinux_state))kallsyms_lookup_name_by_suffix("selinux_state");
  if (!selinux_enforcing && !selinux_state)
    return -21;

  cfv2_lookup_name(cgroup_addrm_files);
  cfv2_lookup_name(cgroup_init_cftypes);

  cfv2_lookup_name(cgroup_procs_write);
  cfv2_lookup_name(css_set_move_task);
  cfv2_lookup_name(__kernfs_create_file);
  cfv2_lookup_name(kernfs_setattr);

  cfv2_lookup_name(get_signal);

  int rc = 0;
  rc = calculate_offsets();
  if (rc < 0)
    return rc;
  // 配置文件需要初始化一下
  if (cftype_ver5 == IZERO) {
    cgroup_freeze_files->seq_show = cgroup_freeze_show;
    cgroup_freeze_files->write = cgroup_freeze_write;
  } else {
    cgroup_freeze_files->seq_show_v4 = cgroup_freeze_show;
    cgroup_freeze_files->write_v4 = cgroup_freeze_write;
  }
  rc = cfv2_resolve_registration();
  if (rc)
    return rc;
  rc = cgroup_init_cftypes(NULL, cgroup_freeze_files);
  if (rc < 0)
    return rc;

  cfv2_hook_func(get_signal, 1, NULL, get_signal_after, NULL);
  cfv2_hook_func(proc_pid_wchan, 4, proc_pid_wchan_before, NULL, NULL);
  cfv2_hook_func(cgroup_addrm_files, 4, NULL, cgroup_addrm_files_after, NULL);
  cfv2_hook_func(cgroup_procs_write, 4, NULL, cgroup_procs_write_after, NULL);
  cfv2_hook_func(css_set_move_task, 4, NULL, css_set_move_task_after, NULL);
  // 高版本内核会自动处理所有者, 不再需要手动更改
  if (cgroup_base_files_ver5 != IZERO) {
    cfv2_hook_func(__kernfs_create_file, 8, NULL, __kernfs_create_file_after, NULL);
  }

  if (!event || strcmp(event, "load-file")) {
    cfv2_hook_func(do_filp_open, 3, NULL, do_filp_open_after, NULL);
  }

  rc = cfv2_register_existing_groups();
  if (rc)
    goto fail_hooks;
  return 0;

fail_hooks:
  inline_hook_exit(NULL);
  return rc;
}

/* 返回固定控制应答。ctl_args 未使用，out_msg/outlen 为用户缓冲区及容量。
 * 只复制已初始化字节；缓冲区不足返回 -EINVAL，短拷贝返回 -EFAULT，否则返回 0。
 */
static long inline_hook_control0(const char* ctl_args, char* __user out_msg, int outlen) {
  static const char msg[] = "_(._.)_";
  if (!out_msg || outlen < (int)sizeof(msg))
    return -EINVAL;
  int copied = compat_copy_to_user(out_msg, msg, sizeof(msg));
  return copied == (int)sizeof(msg) ? 0 : -EFAULT;
}

/* 撤销本模块已安装回调，reserved 未使用；返回 0，可重复处理部分初始化。
 * 不调用全局 unhook，不宣称在途回调或已发布 cftype 的生命周期已得到验证。
 */
static long inline_hook_exit(void* __user reserved) {
  cfv2_unhook_func(do_filp_open, NULL, do_filp_open_after);
  cfv2_unhook_func(__kernfs_create_file, NULL, __kernfs_create_file_after);
  cfv2_unhook_func(css_set_move_task, NULL, css_set_move_task_after);
  cfv2_unhook_func(cgroup_procs_write, NULL, cgroup_procs_write_after);
  cfv2_unhook_func(cgroup_addrm_files, NULL, cgroup_addrm_files_after);
  cfv2_unhook_func(proc_pid_wchan, proc_pid_wchan_before, NULL);
  cfv2_unhook_func(get_signal, NULL, get_signal_after);

  return 0;
}

KPM_INIT(inline_hook_init);
KPM_CTL0(inline_hook_control0);
KPM_EXIT(inline_hook_exit);
