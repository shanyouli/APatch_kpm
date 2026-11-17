# fgetpriority KPM 移植原型

当前为**只读预检原型**，尚未实现补丁安装事务，不能用于过滤优先级查询。
初始化成功完成预检后仍返回 `-EOPNOTSUPP`；不会修改任何内核调用点。

目标仅为 `folk_patched_115404_0.13.9_mefi.img` 提取出的内核，SHA-256 为 `5946dc4ee4dac4f47dc1404dd9b008b110c8d32dc27c20de049699c7d7110900`。
该目标未启用 `CONFIG_USER_NS`；本原型的条件逻辑不支持其他 user namespace 配置。

## 已实现

- 原包在初始 user namespace 下的 seccomp、应用 UID 和 Android 多用户 UID 条件。
- 四个 syscall 的函数指纹、`find_user` 调用指令和 B/BL 距离预检。
- 镜像中 KP 卸载入口的字节指纹核对。
- 无结构体偏移依赖的 ARM64 KPM 编译。无静态/动态偏移模式区别，不附布局 JSON。

## 尚未完成

- 补丁安装、失败回滚、指令冲突处理及卸载恢复。
- 在实际 KP 上核验只读预检、CFI 和运行时导入。
- 独立审计、真机测试和冻结候选身份。

镜像内加载器在 exit 前释放 RCU 读锁，但仍忽略退出错误并释放模块代码；若恢复补丁失败或遇到调用点被其他模块改写，仅返回错误无法避免悬空代码引用。
正式启用前需要明确可拒绝释放的生命周期机制或其他经审计的冲突处理方案。

## 构建

使用提供 `--target=aarch64-none-elf` 的 Clang 与 LLD：

```sh
make -C fgetpriority CC=clang LD=ld.lld OUT_DIR=/tmp/fgp-new-output
clang -Wall -Wextra -Werror fgetpriority/tests/test_policy.c -o /tmp/fgp-policy-test
/tmp/fgp-policy-test
```

输出为 `fgetpriority_0.1.0_preflight.kpm`；请勿将其误认为可工作的过滤模块或正式候选。
当前目录已接入 CI 自动选择，构建并上传预检 KPM。CI 构建与产物门禁通过只证明可编译及产物格式正确，不代表过滤功能已完成。
Makefile 默认使用 Clang 与 LLD，并允许命令行覆盖工具链；只使用当前 KP SDK，不提供旧版本兼容构建分支。

## 来源

策略和过滤包装器移植自相邻 `fgetpriority` 仓库的 `kernel/routine.h`、`routine_raw.c`，源提交 `49f5cd028b968eed94424046ab657c56dd58fa57`，保留 GPL-2.0-only 和原作者版权。
分析工具及结果说明位于 `Developer/tools/inspect_fgetpriority_target.py` 与 `Developer/reports/fgetpriority-target-analysis.md`。

这是 Developer 探索性实现与自检，不是独立审计或真机结论。
