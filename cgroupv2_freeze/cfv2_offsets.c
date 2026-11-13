// task_state_ptr
static inline volatile long *task_state_ptr(struct task_struct *task) {
  volatile long *state = (volatile long *)((uintptr_t)task + struct_offset.task_struct_state);
  return state;
}
// task_flags
static inline unsigned int task_flags(struct task_struct *task) {
  unsigned int flags = *(unsigned int *)((uintptr_t)task + struct_offset.task_struct_flags);
  return flags;
}
// task_flags_ptr
static inline unsigned int *task_flags_ptr(struct task_struct *task) {
  unsigned int *flags = (unsigned int *)((uintptr_t)task + struct_offset.task_struct_flags);
  return flags;
}
// task_jobctl
static inline unsigned long task_jobctl(struct task_struct *task) {
  unsigned long jobctl = *(unsigned long *)((uintptr_t)task + struct_offset.task_struct_jobctl);
  return jobctl;
}
// task_jobctl_ptr
static inline unsigned long *task_jobctl_ptr(struct task_struct *task) {
  unsigned long *jobctl = (unsigned long *)((uintptr_t)task + struct_offset.task_struct_jobctl);
  return jobctl;
}
// task_signal
static inline struct signal_struct *task_signal(struct task_struct *task) {
  struct signal_struct *signal = *(struct signal_struct **)((uintptr_t)task + struct_offset.task_struct_signal);
  return signal;
}
// signal_group_exit_task
static inline struct task_struct *signal_group_exit_task(struct signal_struct *sig) {
  struct task_struct *group_exit_task =
      *(struct task_struct **)((uintptr_t)sig + struct_offset.signal_struct_group_exit_task);
  return group_exit_task;
}
// signal_flags
static inline unsigned int signal_flags(struct signal_struct *sig) {
  unsigned int flags = *(unsigned int *)((uintptr_t)sig + struct_offset.signal_struct_flags);
  return flags;
}
// seq_file_private
static inline struct kernfs_open_file *seq_file_private(struct seq_file *seq) {
  struct kernfs_open_file *private = *(struct kernfs_open_file **)((uintptr_t)seq + struct_offset.seq_file_private);
  return private;
}
// cgroup_flags_ptr
static inline unsigned long *cgroup_flags_ptr(struct cgroup *cgrp) {
  unsigned long *flags = (unsigned long *)((uintptr_t)cgrp + struct_offset.cgroup_flags);
  return flags;
}
// css_set_dfl_cgrp
static inline struct cgroup *css_set_dfl_cgrp(struct css_set *cset) {
  struct cgroup *cgrp = *(struct cgroup **)((uintptr_t)cset + struct_offset.css_set_dfl_cgrp);
  return cgrp;
}
// subprocess_info_argv
static inline char **subprocess_info_argv(struct subprocess_info *sub_info) {
  char **argv = *(char ***)((uintptr_t)sub_info + struct_offset.subprocess_info_argv);
  return argv;
}

/* 核对回填注册所需的共同布局。无参数，成功返回 0，未知形态返回负值。
 * 窗口来自 miuiportspatched 目标：cftype 游标/步长、两个 cgroup 的同名 kn
 * 读取，以及 CSS_NO_REF 检查；不按版本号或参考内核填写字段。
 */
static long calculate_registration_geometry(void) {
  if (cftype_ver5 != IZERO || !cfv2_base_files)
    return -EOPNOTSUPP;

  uint32_t* source = (uint32_t*)cgroup_init_cftypes;
  int cursor = -1;
  bool stride_found = false;
  for (u32 i = 0; i < 0x30; i++) {
    uint32_t insn = source[i];
    if (inst_get_add_imm_sf(insn) != 1 || inst_get_add_imm_sh(insn) != 0)
      continue;
    if (inst_get_add_imm_rn(insn) == 1 && inst_get_add_imm_imm(insn) == offsetof(struct cftype, kf_ops))
      cursor = inst_get_add_imm_rd(insn);
    else if (cursor >= 0 && inst_get_add_imm_rn(insn) == cursor && inst_get_add_imm_rd(insn) == cursor
             && inst_get_add_imm_imm(insn) == sizeof(struct cftype))
      stride_found = true;
  }
  if (!stride_found) {
    logkm("cftype stride does not match the module definition\n");
    return -EOPNOTSUPP;
  }

  void* cgroup_path_ns_locked;
  cfv2_lookup_name(cgroup_path_ns_locked);
  source = (uint32_t*)cgroup_path_ns_locked;
  for (u32 i = 0; i + 1 < 0x28; i++) {
    if (inst_get_ldr_imm_uint_size(source[i]) == 3 && inst_get_ldr_imm_uint_rn(source[i]) == 0
        && inst_get_ldr_imm_uint_size(source[i + 1]) == 3 && inst_get_ldr_imm_uint_rn(source[i + 1]) != 0
        && inst_get_ldr_imm_uint_imm(source[i]) == inst_get_ldr_imm_uint_imm(source[i + 1])) {
      struct_offset.cgroup_kn = inst_get_ldr_imm_uint_imm(source[i]);
      break;
    }
  }

  source = (uint32_t*)cgroup_kn_lock_live;
  for (u32 i = 1; i + 1 < 0x10; i++) {
    if (inst_get_ldr_imm_uint_size(source[i - 1]) == 3
        && inst_get_ldr_imm_uint_rt(source[i - 1]) == inst_get_ldrb_imm_uint_rn(source[i])
        && inst_get_ldrb_imm_uint_rt(source[i]) == inst_get_tbnz_rt(source[i + 1])
        && inst_get_tbnz_bit(source[i + 1]) == 0) {
      struct_offset.css_flags = inst_get_ldrb_imm_uint_imm(source[i]);
      break;
    }
  }
  void* __lock_task_sighand;
  cfv2_lookup_name(__lock_task_sighand);
  unsigned long raw_spin_lock_addr = kallsyms_lookup_name_by_suffix("_raw_spin_lock");
  if (!raw_spin_lock_addr)
    return -ENOENT;
  source = (uint32_t*)__lock_task_sighand;
  struct_offset.sighand_siglock = -1;
  for (u32 i = 2; i + 2 < 0x20; i++) {
    int pointer_reg = inst_get_ldr_imm_uint_rt(source[i - 2]);
    int lock_reg = inst_get_add_imm_rd(source[i]);
    if (inst_get_ldr_imm_uint_size(source[i - 2]) == 3 && pointer_reg >= 0
        && inst_get_cbz_rt(source[i - 1]) == pointer_reg
        && inst_get_add_imm_sf(source[i]) == 1 && inst_get_add_imm_sh(source[i]) == 0
        && inst_get_add_imm_rn(source[i]) == pointer_reg
        && inst_get_mov_reg_sf(source[i + 1]) == 1 && inst_get_mov_reg_rm(source[i + 1]) == lock_reg
        && inst_get_mov_reg_rd(source[i + 1]) == 0 && inst_is_bl(source[i + 2])
        && (unsigned long)&source[i + 2] + inst_get_bl_label(source[i + 2]) == raw_spin_lock_addr) {
      struct_offset.sighand_siglock = inst_get_add_imm_imm(source[i]);
      break;
    }
  }
  if (struct_offset.sighand_siglock < 0 || struct_offset.sighand_siglock > 0x4000
      || (struct_offset.sighand_siglock & 3)) {
    logkm("native sighand lock geometry unresolved\n");
    return -EOPNOTSUPP;
  }
  if (struct_offset.cgroup_kn < 0 || struct_offset.cgroup_kn > 0x1000 || (struct_offset.cgroup_kn & 7)
      || struct_offset.css_flags < 0 || struct_offset.css_flags > 0x400 || (struct_offset.css_flags & 3)) {
    logkm("cgroup registration geometry unresolved\n");
    return -EOPNOTSUPP;
  }
  logkm("registration geometry: cgroup.kn=%d css.flags=%d cftype.size=%zu\n",
        struct_offset.cgroup_kn, struct_offset.css_flags, sizeof(struct cftype));
  return 0;
}

/* 从既有固定窗口取得模块所需布局；无参数，成功返回 0，缺项返回负值。
 * 不扩大窗口或按版本猜偏移；函数名查询使用 KP 后缀接口，零 state 偏移合法。
 */
static long calculate_offsets(void) {
  // 获取 css_task_iter_start 版本, 以参数数量做判断
  uint32_t *css_task_iter_start_src = (uint32_t *)css_task_iter_start;
  for (u32 i = 0; i < 0x10; i++) {
    if (inst_is_ret(css_task_iter_start_src[i])) {
      break;
    } else if (inst_get_mov_reg_rm(css_task_iter_start_src[i]) == 2) {
      css_task_iter_start_ver5 = IZERO;
      break;
    }
  }
#ifdef CONFIG_DEBUG
  logkm("css_task_iter_start_ver5=0x%llx\n", css_task_iter_start_ver5);
#endif /* CONFIG_DEBUG */

  // 获取 cgroup_kn_lock_live 版本, 以参数数量做判断
  uint32_t *cgroup_kn_lock_live_src = (uint32_t *)cgroup_kn_lock_live;
  for (u32 i = 0; i < 0x10; i++) {
    if (inst_is_ret(cgroup_kn_lock_live_src[i])) {
      break;
    } else if (inst_get_mov_reg_rm(cgroup_kn_lock_live_src[i]) == 1
               || inst_get_uxtb_rn(cgroup_kn_lock_live_src[i]) == 1) {
      cgroup_kn_lock_live_ver5 = IZERO;
      break;
    }
  }
#ifdef CONFIG_DEBUG
  logkm("cgroup_kn_lock_live_ver5=0x%llx\n", cgroup_kn_lock_live_ver5);
#endif /* CONFIG_DEBUG */

  // 获取 cftype 版本, 以绑定函数做判断
  int (*cgroup_file_open)(struct kernfs_open_file *of) = NULL;
  cgroup_file_open = (typeof(cgroup_file_open))kallsyms_lookup_name_by_suffix("cgroup_file_open");

#ifdef CONFIG_DEBUG
  logkm("cgroup_file_open %llx\n", cgroup_file_open);
#endif /* CONFIG_DEBUG */
  if (cgroup_file_open) {
    cftype_ver5 = IZERO;
  }
#ifdef CONFIG_DEBUG
  logkm("cftype_ver5=0x%llx\n", cftype_ver5);
#endif /* CONFIG_DEBUG */

  // 获取 cgroup_base_files 版本, 以变量名做判断
  struct cftype *cgroup_base_files = NULL;
  cgroup_base_files = (typeof(cgroup_base_files))kallsyms_lookup_name_by_suffix("cgroup_base_files");

#ifdef CONFIG_DEBUG
  logkm("cgroup_base_files %llx\n", cgroup_base_files);
#endif /* CONFIG_DEBUG */
  cfv2_base_files = cgroup_base_files;
  if (cgroup_base_files) {
    cgroup_base_files_ver5 = IZERO;
    if (!cgroup_file_open) {
      logkm("cftype layout unresolved: base files present but cgroup_file_open unavailable\n");
      return -EOPNOTSUPP;
    }
  }
#ifdef CONFIG_DEBUG
  logkm("cgroup_base_files_ver5=0x%llx\n", cgroup_base_files_ver5);
#endif /* CONFIG_DEBUG */

  // 获取 task_struct->jobctl
  void (*task_clear_jobctl_trapping)(struct task_struct *t);
  cfv2_lookup_name(task_clear_jobctl_trapping);

  uint32_t *task_clear_jobctl_trapping_src = (uint32_t *)task_clear_jobctl_trapping;
  for (u32 i = 0; i < 0x10; i++) {
    if (inst_is_ret(task_clear_jobctl_trapping_src[i])) {
      break;
    } else if (inst_get_ldr_imm_uint_size(task_clear_jobctl_trapping_src[i]) == 0b11
               && inst_get_ldr_imm_uint_rn(task_clear_jobctl_trapping_src[i]) == 0) {
      struct_offset.task_struct_jobctl = inst_get_ldr_imm_uint_imm(task_clear_jobctl_trapping_src[i]);
      break;
    }
  }
#ifdef CONFIG_DEBUG
  logkm("task_struct_jobctl=0x%llx\n", struct_offset.task_struct_jobctl);
#endif /* CONFIG_DEBUG */
  if (struct_offset.task_struct_jobctl <= 0)
    return -11;

  // 获取 task_struct->signal
  void (*tty_audit_fork)(struct signal_struct *sig);
  cfv2_lookup_name(tty_audit_fork);

  uint32_t *tty_audit_fork_src = (uint32_t *)tty_audit_fork;
  for (u32 i = 0; i < 0x20; i++) {
    if (inst_is_ret(tty_audit_fork_src[i])) {
      break;
    } else if (i > 0 && inst_get_ldr_imm_uint_size(tty_audit_fork_src[i]) == 0b11
               && inst_is_mrs_sp_el0(tty_audit_fork_src[i - 1])) {
      struct_offset.task_struct_signal = inst_get_ldr_imm_uint_imm(tty_audit_fork_src[i]);
      break;
    }
  }
#ifdef CONFIG_DEBUG
  logkm("task_struct_signal=0x%llx\n", struct_offset.task_struct_signal);
#endif /* CONFIG_DEBUG */
  if (struct_offset.task_struct_signal <= 0)
    return -11;

  // 获取 signal_struct->flags, signal_struct->group_exit_task
  void (*zap_other_threads)(struct task_struct *t);
  cfv2_lookup_name(zap_other_threads);

  uint32_t *zap_other_threads_src = (uint32_t *)zap_other_threads;
  for (u32 i = 0; i < 0x20; i++) {
    if (inst_is_ret(zap_other_threads_src[i])) {
      break;
    } else if (inst_get_str_imm_uint_rt(zap_other_threads_src[i]) == 31) {
      uint64_t offset = inst_get_str_imm_uint_imm(zap_other_threads_src[i]);  // signal_struct->group_stop_count
      struct_offset.signal_struct_group_exit_task = offset - 0x8;
      struct_offset.signal_struct_flags = offset + 0x4;
      break;
    }
  }
#ifdef CONFIG_DEBUG
  logkm("signal_struct_group_exit_task=0x%llx\n", struct_offset.signal_struct_group_exit_task);
  logkm("signal_struct_flags=0x%llx\n", struct_offset.signal_struct_flags);
#endif /* CONFIG_DEBUG */
  if (struct_offset.signal_struct_group_exit_task <= 0)
    return -11;

  // 获取 task_struct->flags
  bool (*freezing_slow_path)(struct task_struct *p);
  cfv2_lookup_name(freezing_slow_path);

  uint32_t *freezing_slow_path_src = (uint32_t *)freezing_slow_path;
  for (u32 i = 0; i < 0x20; i++) {
    if (inst_is_ret(freezing_slow_path_src[i])) {
      break;
    } else if (inst_get_ldr_imm_uint_size(freezing_slow_path_src[i]) == 0b10
               && inst_get_ldr_imm_uint_rn(freezing_slow_path_src[i]) == 0) {
      struct_offset.task_struct_flags = inst_get_ldr_imm_uint_imm(freezing_slow_path_src[i]);
      break;
    }
  }
#ifdef CONFIG_DEBUG
  logkm("task_struct_flags=0x%llx\n", struct_offset.task_struct_flags);
#endif /* CONFIG_DEBUG */
  if (struct_offset.task_struct_flags <= 0)
    return -11;

  // 获取 task_struct->state
  bool (*schedule_timeout_interruptible)(struct task_struct *p);
  cfv2_lookup_name(schedule_timeout_interruptible);

  uint32_t *schedule_timeout_interruptible_src = (uint32_t *)schedule_timeout_interruptible;
  for (u32 i = 0; i < 0x20; i++) {
    if (inst_is_ret(schedule_timeout_interruptible_src[i])) {
      break;
    } else if (inst_get_str_imm_uint_size(schedule_timeout_interruptible_src[i]) == 0b11) {
      struct_offset.task_struct_state = inst_get_str_imm_uint_imm(schedule_timeout_interruptible_src[i]);
      break;
    }
  }
#ifdef CONFIG_DEBUG
  logkm("task_struct_state=0x%llx\n", struct_offset.task_struct_state);
#endif /* CONFIG_DEBUG */
  if (struct_offset.task_struct_state < 0)
    return -11;

  // 获取 seq_file->private
  int (*cgroup_subtree_control_show)(struct seq_file *seq, void *v);
  cfv2_lookup_name(cgroup_subtree_control_show);

  uint32_t *cgroup_subtree_control_show_src = (uint32_t *)cgroup_subtree_control_show;
  for (u32 i = 0; i < 0x20; i++) {
    if (inst_is_ret(cgroup_subtree_control_show_src[i])) {
      break;
    } else if (inst_get_ldr_imm_uint_size(cgroup_subtree_control_show_src[i]) == 0b11) {
      struct_offset.seq_file_private = inst_get_ldr_imm_uint_imm(cgroup_subtree_control_show_src[i]);
      break;
    }
  }
#ifdef CONFIG_DEBUG
  logkm("seq_file_private=0x%llx\n", struct_offset.seq_file_private);
#endif /* CONFIG_DEBUG */
  if (struct_offset.seq_file_private <= 0)
    return -11;

  // 获取 freezer->state
  void (*cgroup_freezing)(struct task_struct *task);
  cfv2_lookup_name(cgroup_freezing);

  uint32_t *cgroup_freezing_src = (uint32_t *)cgroup_freezing;
  for (u32 i = 0; i + 1 < 0x20; i++) {
    if (inst_is_ret(cgroup_freezing_src[i])) {
      break;
    } else if (inst_get_ldr_imm_uint_size(cgroup_freezing_src[i]) == 0b10
               && inst_get_tst_imm_sf(cgroup_freezing_src[i + 1]) == 0
               && inst_get_tst_imm_imm(cgroup_freezing_src[i + 1]) == 6) {
      struct_offset.freezer_state = inst_get_ldr_imm_uint_imm(cgroup_freezing_src[i]);
      struct_offset.cgroup_flags = struct_offset.freezer_state;
      break;
    }
  }
#ifdef CONFIG_DEBUG
  logkm("freezer_state=0x%llx\n", struct_offset.freezer_state);
#endif /* CONFIG_DEBUG */
  if (struct_offset.freezer_state <= 0)
    return -11;

  // 获取 task_struct->css_set
  void (*cgroup_fork)(struct task_struct *child);
  cfv2_lookup_name(cgroup_fork);

  uint32_t *cgroup_fork_src = (uint32_t *)cgroup_fork;
  for (u32 i = 0; i < 0x10; i++) {
    if (inst_is_ret(cgroup_fork_src[i])) {
      break;
    } else if (inst_get_str_imm_uint_size(cgroup_fork_src[i]) == 0b11) {
      struct_offset.task_struct_css_set = inst_get_str_imm_uint_imm(cgroup_fork_src[i]);
      break;
    }
  }
#ifdef CONFIG_DEBUG
  logkm("task_struct_css_set=0x%llx\n", struct_offset.task_struct_css_set);
#endif /* CONFIG_DEBUG */
  if (struct_offset.task_struct_css_set <= 0)
    return -11;

  // 获取 css_set->dfl_cgrp
  struct css_set kvar_def(init_css_set);
  kvar_lookup_name(init_css_set);
  if (!kvar(init_css_set)) {
    logkm("required symbol init_css_set not found\n");
    return -ENOENT;
  }
  cfv2_init_css_set = kvar(init_css_set);
  // 保留既有 dom_cset 自引用识别；没有目标证据时不再默认 dfl_cgrp 为 0x48。
  struct_offset.css_set_dfl_cgrp = -1;
  uint64_t *init_css_set_src = (uint64_t *)kvar(init_css_set);
  for (u32 i = 0; i < 0x10; i++) {
    if (init_css_set_src[i] == (uint64_t)kvar(init_css_set)) {
      struct_offset.css_set_dfl_cgrp = (i + 1) * 8;
      break;
    }
  }
#ifdef CONFIG_DEBUG
  logkm("init_css_set=0x%llx\n", kvar(init_css_set));
  logkm("css_set_dfl_cgrp=0x%llx\n", struct_offset.css_set_dfl_cgrp);
#endif /* CONFIG_DEBUG */
  if (struct_offset.css_set_dfl_cgrp <= 0)
    return -11;

  // 获取 subprocess_info->path, subprocess_info->argv
  uint32_t *call_usermodehelper_exec_src = (uint32_t *)kfunc(call_usermodehelper_exec);
  for (u32 i = 0; i < 0x20; i++) {
    if (inst_is_ret(call_usermodehelper_exec_src[i])) {
      break;
    } else if (inst_get_ldr_imm_uint_size(call_usermodehelper_exec_src[i]) == 0b11
               && inst_get_ldr_imm_uint_rn(call_usermodehelper_exec_src[i]) == 0) {
      struct_offset.subprocess_info_path = inst_get_ldr_imm_uint_imm(call_usermodehelper_exec_src[i]);
      struct_offset.subprocess_info_argv = struct_offset.subprocess_info_path + 0x8;
      break;
    }
  }
#ifdef CONFIG_DEBUG
  logkm("subprocess_info_path=0x%llx\n", struct_offset.subprocess_info_path);
  logkm("subprocess_info_argv=0x%llx\n", struct_offset.subprocess_info_argv);
#endif /* CONFIG_DEBUG */
  if (struct_offset.subprocess_info_path <= 0)
    return -11;

  return calculate_registration_geometry();
}
