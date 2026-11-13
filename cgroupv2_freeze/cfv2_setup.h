/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef __CFV2_SETUP_H
#define __CFV2_SETUP_H

/* 延迟初始化命令：复用系统已挂载的层级，分别检查两个分组的内核接口。
 * 不卸载系统挂载、不递归改变 UID/PID 子树，也不把普通文件伪装成 cgroup.freeze。
 * 缺少挂载、接口或权限时以非零状态退出；已有分组缺少接口须在内核侧另行处理。
 */
static const char cfv2_setup_cmd[] =
    "set -eu\n"
    "root=/sys/fs/cgroup\n"
    "if [ ! -f \"$root/cgroup.controllers\" ] && [ ! -f \"$root/cgroup.procs\" ]; then\n"
    "  echo 'cgroupv2_freeze: existing cgroup mount required' >&2\n"
    "  exit 1\n"
    "fi\n"
    "for group in frozen unfrozen; do\n"
    "  mkdir -p \"$root/$group\"\n"
    "  if [ ! -f \"$root/$group/cgroup.freeze\" ] || [ ! -f \"$root/$group/cgroup.procs\" ]; then\n"
    "    echo \"cgroupv2_freeze: missing kernel interface in $root/$group\" >&2\n"
    "    exit 1\n"
    "  fi\n"
    "  chown system:system \"$root/$group\" \"$root/$group/cgroup.freeze\" \"$root/$group/cgroup.procs\"\n"
    "done\n"
    "echo 1 > \"$root/frozen/cgroup.freeze\"\n"
    "echo 0 > \"$root/unfrozen/cgroup.freeze\"\n";

#endif /* __CFV2_SETUP_H */
