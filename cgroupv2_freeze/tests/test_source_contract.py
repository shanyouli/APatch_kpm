#!/usr/bin/env python3
"""不编译的模块自检：源码契约检查与隔离目录中的真实 shell 初始化命令测试。

仅验证本轮修改的保护条件与脚本分支，不证明 C 语法、偏移正确性或真机可用性。
不调用编译器、make、ADB、真实挂载或 chown。
"""

import ast
from pathlib import Path
import re
import subprocess
import tempfile
import unittest


MODULE = Path(__file__).resolve().parents[1]


def setup_command():
    """读取生产命令字符串；无参数，返回拼接后的 shell 文本，解析失败抛异常。"""
    source = (MODULE / "cfv2_setup.h").read_text()
    match = re.search(r'static const char cfv2_setup_cmd\[\] =\s*((?:"(?:\\.|[^"\\])*"\s*)+);', source)
    if not match:
        raise ValueError("无法提取完整的生产命令字符串")
    return "".join(ast.literal_eval(s) for s in re.findall(r'"(?:\\.|[^"\\])*"', match.group(1)))


class SourceContractTests(unittest.TestCase):
    """检查本轮源码保护条件的存在；不执行或模拟 ARM64 偏移推导。"""

    def test_suffix_lookup_and_sdk_guards(self):
        """无参数；断言自有符号统一后缀查询且 SDK 指针查询包含缺失检查。"""
        source = (MODULE / "cgroupv2_freeze.c").read_text()
        offsets = (MODULE / "cfv2_offsets.c").read_text()
        utils = (MODULE / "cfv2_utils.h").read_text()
        self.assertNotRegex(source + offsets, r"\bkallsyms_lookup_name\(")
        self.assertNotRegex(source + offsets, r"(?<!_)\blookup_name\(")
        self.assertNotRegex(source, r"(?<!_)\bkfunc_lookup_name\(")
        self.assertIn("kallsyms_lookup_name_by_suffix(#func)", utils)
        self.assertIn("if (!kfunc(func))", utils)
        self.assertIn("return -ENOENT;", utils)
        self.assertIn("if (!cgroup_file_open)", offsets)
        self.assertIn("return -EOPNOTSUPP;", offsets)

    def test_scan_boundaries_and_unknown_sentinels(self):
        """无参数；断言回看/前瞻边界、零 state 偏移及无固定 dfl_cgrp 回退。"""
        source = (MODULE / "cgroupv2_freeze.c").read_text()
        offsets = (MODULE / "cfv2_offsets.c").read_text()
        self.assertIn("i > 0 && inst_get_ldr_imm_uint_size(tty_audit_fork_src[i])", offsets)
        self.assertIn("for (u32 i = 0; i + 1 < 0x20; i++)", offsets)
        self.assertIn(".task_struct_state = -1", source)
        self.assertIn("if (struct_offset.task_struct_state < 0)", offsets)
        self.assertIn("struct_offset.css_set_dfl_cgrp = -1;", offsets)
        self.assertNotIn("struct_offset.css_set_dfl_cgrp = 0x48;", offsets)
        self.assertIn("if (!kvar(init_css_set))", offsets)

    def test_android_shell_and_local_hook_cleanup(self):
        """无参数；断言 Android shell、失败传播和临时回调配对撤销。"""
        source = (MODULE / "cgroupv2_freeze.c").read_text()
        self.assertIn('"/system/bin/sh"', source)
        self.assertIn("rc = call_usermodehelper", source)
        self.assertIn("if (!argv || !argv[0])", source)
        self.assertIn("hook_unwrap(kfunc(call_usermodehelper_exec), call_usermodehelper_exec_before, NULL)", source)
        self.assertLess(source.index("hook_unwrap(do_filp_open, NULL, do_filp_open_after)"),
                        source.index("int rc = run_cmd(cmd)"))


    def test_existing_and_future_kernel_registration(self):
        """无参数；注册必须进入 init 并覆盖已有分组，未来回调过滤 controller/自有表。"""
        source = (MODULE / "cgroupv2_freeze.c").read_text()
        registration = (MODULE / "cfv2_registration.c").read_text()
        self.assertIn("rc = cfv2_register_existing_groups();", source)
        self.assertIn("kfunc(mutex_lock)(cfv2_cgroup_mutex)", registration)
        self.assertIn("css_for_each_descendant_pre(css, &cfv2_root_cgroup->self)", registration)
        self.assertIn("cgroup_addrm_files(&cgrp->self, cgrp, cgroup_freeze_files, is_add)", registration)
        self.assertIn("(struct cftype*)args->arg2 != cfv2_base_files", registration)
        self.assertIn("args->ret = ret;", registration)
        self.assertNotIn("run_cmd", registration)

    def test_freeze_keeps_native_signal_processing(self):
        """无参数；冻结只在原生 get_signal 之后等待，锁住 jobctl 且不盲清 pending。"""
        source = (MODULE / "cgroupv2_freeze.c").read_text()
        self.assertIn("cfv2_hook_func(get_signal, 1, NULL, get_signal_after, NULL)", source)
        self.assertIn("if (!args->ret && (task_jobctl(current) & JOBCTL_TRAP_FREEZE))", source)
        self.assertIn("cfv2_lock_sighand(task, &irq_flags)", source)
        self.assertIn("signal_wake_up_state(current, 0)", source)
        self.assertNotIn("get_signal_before", source)
        self.assertNotIn("clear_thread_flag(TIF_SIGPENDING)", source)

    def test_control_reply_uses_initialized_bytes(self):
        """无参数；固定应答不能泄露栈缓冲区尾部，且必须检查容量与拷贝结果。"""
        source = (MODULE / "cgroupv2_freeze.c").read_text()
        self.assertIn('static const char msg[] = "_(._.)_";', source)
        self.assertIn("if (!out_msg || outlen < (int)sizeof(msg))", source)
        self.assertIn("return copied == (int)sizeof(msg) ? 0 : -EFAULT;", source)
        self.assertNotIn("char msg[64]", source)

    def test_hook_failure_only_cleans_installed_callbacks(self):
        """无参数；断言失败回滚按安装标志清理，不调用可能影响别人的全局 unhook。"""
        source = (MODULE / "cgroupv2_freeze.c").read_text()
        utils = (MODULE / "cfv2_utils.h").read_text()
        self.assertNotRegex(source, r"\bunhook(?:_func)?\(")
        self.assertIn("func##_hooked = true;", utils)
        self.assertIn("if (func##_hooked)", utils)
        self.assertIn("goto fail_hooks;", utils)
        self.assertIn("fail_hooks:\n  inline_hook_exit(NULL);", source)
        self.assertEqual(source.count("cfv2_unhook_func("), 7)


class SetupCommandTests(unittest.TestCase):
    """隔离执行生产 shell 字符串；仅重定向根路径并模拟内核创建文件的动作。"""

    def setUp(self):
        """无参数；创建临时层级和操作日志，副作用仅限临时目录。"""
        self.tmp = tempfile.TemporaryDirectory(prefix="cfv2-selftest-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / "cgroup"
        self.root.mkdir()
        self.ops = Path(self.tmp.name) / "operations"
        self.ops.touch()

    def root_interface(self, name="cgroup.controllers"):
        """在临时根创建 name 接口文件；无返回值，不模拟 controller 的内容。"""
        (self.root / name).touch()

    def group(self, name, freeze="0", with_interface=True):
        """创建 name 分组；freeze 为初值，with_interface 控制接口缺失，返回目录。"""
        path = self.root / name
        path.mkdir()
        (path / "cgroup.procs").touch()
        if with_interface:
            (path / "cgroup.freeze").write_text(freeze + "\n")
        return path

    def run_setup(self, create_interfaces=True, fail_chown=False, fail_mkdir=False):
        """在隔离根执行脚本；参数控制失败分支，返回进程结果，超时抛异常。"""
        script = setup_command().replace("root=/sys/fs/cgroup", f"root='{self.root}'")
        wrappers = f"""
ops='{self.ops}'
mkdir() {{
  printf 'mkdir %s\\n' "$*" >> "$ops"
  [ {int(fail_mkdir)} = 0 ] || return 1
  for dir do :; done
  existed=0
  [ ! -d "$dir" ] || existed=1
  command mkdir "$@" || return 1
  if [ "$existed" = 0 ] && [ {int(create_interfaces)} = 1 ]; then
    : > "$dir/cgroup.procs"
    printf '0\\n' > "$dir/cgroup.freeze"
  fi
}}
chown() {{
  printf 'chown %s\\n' "$*" >> "$ops"
  [ {int(fail_chown)} = 0 ]
}}
mount() {{ printf 'FORBIDDEN mount\\n' >> "$ops"; return 99; }}
umount() {{ printf 'FORBIDDEN umount\\n' >> "$ops"; return 99; }}
"""
        result = subprocess.run(["/bin/sh"], input=wrappers + script, text=True,
                                capture_output=True, timeout=5)
        self.assertNotIn("FORBIDDEN", self.ops.read_text())
        return result

    def test_shell_syntax(self):
        """无参数；仅解析生产脚本，不执行任何命令。"""
        result = subprocess.run(["/bin/sh", "-n"], input=setup_command(), text=True,
                                capture_output=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotRegex(setup_command(), r"(?m)^\s*(?:mount|umount)\b")
        self.assertNotIn("chown -R", setup_command())

    def test_existing_groups_and_empty_controllers(self):
        """空 controllers 仍表示 v2 接口存在；分别恢复两个分组的预期值。"""
        self.root_interface()
        self.group("frozen")
        self.group("unfrozen", freeze="1")
        result = self.run_setup()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.root / "frozen/cgroup.freeze").read_text(), "1\n")
        self.assertEqual((self.root / "unfrozen/cgroup.freeze").read_text(), "0\n")

    def test_missing_unfrozen_created_independently(self):
        """frozen 已存在不应阻止创建 unfrozen；接口由模拟内核产生。"""
        self.root_interface()
        self.group("frozen")
        result = self.run_setup()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue((self.root / "unfrozen/cgroup.freeze").is_file())

    def test_existing_group_without_interface_is_not_faked(self):
        """当前手机的目录存在但接口缺失形态必须失败，不能创建普通 freeze 文件。"""
        self.root_interface()
        self.group("frozen", with_interface=False)
        result = self.run_setup()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("missing kernel interface", result.stderr)
        self.assertFalse((self.root / "frozen/cgroup.freeze").exists())
        self.assertFalse((self.root / "unfrozen").exists())

    def test_new_group_without_kernel_interface_fails(self):
        """内核未补接口时失败，不通过 shell 重定向伪造接口。"""
        self.root_interface()
        result = self.run_setup(create_interfaces=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.root / "frozen/cgroup.freeze").exists())

    def test_no_mount_fails_before_creating_groups(self):
        """无根接口时退出，不卸载或猜测挂载路径。"""
        result = self.run_setup()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("existing cgroup mount required", result.stderr)
        self.assertEqual(self.ops.read_text(), "")

    def test_existing_legacy_hierarchy(self):
        """已有 v1 根 cgroup.procs 也可复用；不根据版本号选择路径。"""
        self.root_interface("cgroup.procs")
        result = self.run_setup()
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_chown_failure_does_not_change_freeze(self):
        """权限失败不继续写冻结值。"""
        self.root_interface()
        self.group("frozen")
        result = self.run_setup(fail_chown=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual((self.root / "frozen/cgroup.freeze").read_text(), "0\n")

    def test_mkdir_failure_propagates(self):
        """创建失败立即退出，分组与伪造接口均不存在。"""
        self.root_interface()
        result = self.run_setup(fail_mkdir=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.root / "frozen").exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
