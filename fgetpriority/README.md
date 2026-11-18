# fgetpriority KPM

`0.2.0` 修复原预检件的远距离 `BL` 问题，使用 KP 原生绝对跳转 hook。
成功初始化会注册过滤回调并返回 0，不再主动返回 `-EOPNOTSUPP`。
当前属于 Developer 的实现与离线自检版本，**尚未独立审计或真机验证，不应直接安排加载重试**。

## 行为

- hook `find_user`，但只在四个已验证的优先级 syscall 调用点生效。
- 保留原包的 seccomp、应用 UID 和 Android 多用户 UID 判定。
- 原 `find_user` 先运行；命中过滤后调用 `free_uid` 配平引用并返回空结果，错误码由原 syscall 决定。
- 其他 syscall、PID/进程组路径、系统 UID、同应用 UID、未启用 seccomp 的调用保持原行为。
- 使用原调用的返回地址识别作用域，不依赖全局开关、CPU 标记或任务布局猜测。

## 支持边界

目标仅为 `folk_patched_115404_0.13.9_mefi.img` 对应的内核字节，SHA-256：

```text
5946dc4ee4dac4f47dc1404dd9b008b110c8d32dc27c20de049699c7d7110900
```

目标为 `CONFIG_USER_NS=n`。必须同时通过 syscall、KP 加载器、hook 注册/撤销函数与 `_transit4` 的代码指纹。
同样叫“KP 0.13.9”不表示指纹一致；未知内核、其他 KP 构建和 32 位 compat 路径未声明支持。
本次修复仅针对已记录的启动完成后 Manager 加载路径，未验证早期嵌入加载。

`fgp_target.h` 的数字是指定目标的代码/回调帧契约，不是 Linux 结构体布局偏移。
本模块不读取变化的内核结构体字段，因此只生成一份普通 KPM，不生成 baselines JSON。

## 初始化与退出

初始化先核对依赖和目标代码，再注册一个 after 回调，最后核验完整入口跳板和复制的 transit 字节。
任何核验失败都返回明确阶段错误；不会通过截断地址或忽略失败制造加载成功。

退出使用 `hook_unwrap_remove(..., remove=0)` 只撤销本模块回调，然后调用 `synchronize_rcu_tasks()` 与 `synchronize_sched()` 排空不睡眠回调。
**不调用默认会立即释放 KP 跳板的 unhook/unwrap 路径。** KP 持有的透明跳板保留，后续注册可复用；退出恢复的是原函数行为，而不是把入口机器码恢复成完全相同的字节。
回调不得添加可能主动调度的操作，否则退出同步依据失效。

缺少同步依赖或代码契约不匹配时拒绝初始化。
与其他模块同时 hook 同一函数、运行端文本补丁失败处理及真实退出同步仍需要独立审计。

## 构建与 CI

使用支持 `--target=aarch64-none-elf` 的 Clang、LLD 和宿主 C 编译器：

```sh
make -C fgetpriority CC=clang LD=ld.lld OUT_DIR=/tmp/fgp-new-output
```

`make all` 先运行 UID 策略、调用作用域和 init/exit 宿主回归，再构建 `fgetpriority_0.2.0.kpm`。
现有 CI 会选择本目录并使用同一入口；产物继续由仓库 `tools/artifact_gate.py` 核验。
构建和宿主测试通过不表示设备加载或实际过滤通过。

仅运行宿主测试：

```sh
make -C fgetpriority check OUT_DIR=/tmp/fgp-tests
```

## 验证与来源

- `tests/test_policy.c` 保留原 UID 条件基准。
- `tests/test_scope.c` 验证仅四个原始返回地址可命中过滤作用域。
- `tests/test_init.c` 使用指定镜像的字节切片驱动生产 init/exit，验证远地址、失败分类、引用配平与回调撤销顺序；不模拟内核文本写入或真实 RCU 等待。
- `Developer/tools/emulate_fgetpriority_hook.py` 执行目标 KP 的实际 `hook_prepare` 和 `_transit4` 指令，核验绝对跳板及 LR 帧契约；不执行真实 hook 安装。

策略源自上游 `fgetpriority` 的 `kernel/routine.h`、`routine_raw.c`，源提交 `49f5cd028b968eed94424046ab657c56dd58fa57`，保留 GPL-2.0-only 和原作者版权。

如果设备保留有 pstore/Oops，先保留现场并交维护者核验；不得直接使用新产物反复加载、重启或清理现场。
