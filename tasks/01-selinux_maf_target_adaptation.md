# 01 SELinux MAF 目标内核适配

## 背景

用户提供了源码压缩包 `selinux_maf_fork-main-1794886208355.zip` 与已经嵌入 KernelPatch 的目标镜像 `folk_patched_115404_0.13.9_mivk.img`。源码已解压到本地调查目录，目标镜像提取出的内核版本为 `4.14.186-perf-ga368196f0bd0`。

目标 boot 镜像 SHA-256：`30325db5c2e35a637e4afb77bd411295e9cd916eee0b05f6ee939d950c1de335`。
提取内核 SHA-256：`4817bfebae787b90a9e659fb4ff42445dae268c279839b7ceaee6bf580a2cc29`。
源码压缩包 SHA-256：`655df46b69bcf4d67930160299614828a99eb0c53c882228d427bf96ee539898`。

已确认的目标证据：

- 目标内核启用 `CONFIG_SECURITY_SELINUX=y`、`CONFIG_KALLSYMS=y`、`CONFIG_KALLSYMS_ALL=y`、`CONFIG_LTO_CLANG=y`、`CONFIG_CFI_CLANG=y`，来源为目标镜像内嵌 IKCONFIG。
- 目标内核的 `selinux_kernel_status_page` 在 `0x5f3658`，但 `sel_open_handle_status` 的机器码在 `0x5d8878` 内直接完成 page 分配和初始化，没有调用 `selinux_kernel_status_page`（离线反汇编证据：`local/selinux-maf-investigation/status-open-full.txt`）。因此源码只 hook `selinux_kernel_status_page`，无法覆盖目标内核实际的 status 打开路径。
- 目标内核的符号实际使用 LTO/CFI 名称：`sel_write_access$...`、`sel_write_context$...`、`selinux_setprocattr$...`、`context_struct_compute_av.llvm...`。这些目标入口可由源码的后缀扫描命中，但普通独立函数名与 CFI 跳板必须分别处理。
- 目标内核版本低于 KernelPatch 内置 `selinux_hide` 的支持阈值 `4.19`，所以镜像中虽然包含 `selinux_hide` 代码字符串，但不能据此认为该内置功能会在此 4.14 内核启用。它不是本轮失效原因的充分解释。
- 源码的 `init()` 即使 `snapshot_clean_policy()` 没有取得策略副本，仍继续安装部分 hook 并返回成功；`enter_clean_eval_scope()` 在没有 `g_clean_policydb` 时直接失败，查询随后走原始策略路径。这可解释“模块能加载但没有效果”。源码位置：`selinux_hook.c` 的策略快照、scope 入口和 init 路径。

本轮结论属于 Developer 的离线分析，不是独立审计，也不是实机结论。

## 非目标

- 不修改目标 boot.img，不刷机，不执行真机加载或卸载。
- 不把镜像内已有的 KernelPatch `selinux_hide` 字符串误判为已启用功能。
- 不按内核版本号硬猜结构体偏移；本轮优先使用目标机器码和符号证据。
- 不修改 Auditor、Tester、metadata、docs 或 tools 路径。

## 任务清单

### X1（P0）让 status 读取覆盖 4.14 的真实路径

事实：目标 `sel_open_handle_status` 内联了 status page 的分配，源码仅 hook `selinux_kernel_status_page()`；因此 status read/mmap 的 `private_data` 仍然指向原始 page。目标函数机器码包含 `struct file` 私有数据写入偏移 `+0xc8`，read/mmap 随后分别从 `file + 0xc8` 读取 page。

待办：

- [ ] 在 KPM 中增加目标 4.14 status 打开路径的适配，优先复用现有 `sel_read_handle_status` / `sel_mmap_handle_status` hook 机制，在打开后把 app UID 对应的 `private_data` 改为 fake status page，或在 read/mmap 入口稳定返回伪造内容。
- [ ] 对 `struct file` 私有数据位置、`sel_read_handle_status` 和 `sel_mmap_handle_status` 的参数 ABI 建立目标机器码证据；只接受已核对的目标入口，证据不足则保持 status 功能关闭并输出明确日志。
- [ ] 保留非 app UID 的原始行为；分别核对 status.sequence（更新同步序列）、status.policyload（策略加载序列）与 access avd.seqno 的原生语义，不把这些字段当成同一个计数器。

验证：

- 离线反汇编重新确认目标打开/read/mmap 数据流与实现假设一致。
- 构建后检查 KPM 的未定义导入、AArch64 重定位和 hook 参数数量。
- 运行时由 Tester 使用 `/sys/fs/selinux/status` 的 read 与 mmap 判据分别验证。

收益/成本：收益高；成本中高，涉及目标函数参数与 `struct file` 私有字段的运行时安全处理。

### X2（P0）让策略快照失败时明确失败或提供目标兼容捕获

事实：源码从 `/.magisk/selinux/load` 或 `.magisk/selinux/load` 读取策略；目标 4.14 的启动时机与该路径是否存在尚未从镜像确认。快照失败后 `init()` 仍返回 0，但 clean policydb 不存在时 `enter_clean_eval_scope()` 返回 false，access/context/setprocattr 继续走原策略。

待办：

- [ ] 为策略快照增加可观测的失败原因与最终工作状态，区分“文件不存在”“读取 ABI 不匹配”“policydb_read 失败”“快照尚未准备好”。
- [ ] 根据目标启动流程确认策略载荷来源；如果只能在 `security_load_policy` 捕获，必须用目标 4.14 的 `security_load_policy` 机器码确认参数为 `(selinux_state, data, len)`，并只在数据指针与长度通过边界检查时复制。
- [ ] 决定策略快照缺失时的契约：建议让 `mode` 返回 `POLICYDB_REQ` 并禁止宣称功能已启用，避免“可加载但无效果”的假成功。
- [ ] 不用 `g_clean_policy_has_magisk` 作为是否启用的唯一条件；必须以完整 policydb 快照和独立对象生命周期为准。

验证：

- 离线核对 `security_load_policy` 目标入口：目标机器码保存 `x0` 为 state、`x1/x2` 为 data/len，支持当前 fallback 参数选择，但不能替代真机捕获证据。
- 增加宿主可运行的负例：无策略文件、长度越界、policydb_read 返回错误时不得进入 clean-eval。
- 真机报告记录启动时快照结果和 `mode` 状态。

收益/成本：收益高；成本中。

### X3（P1）修正符号与 hook 安装的目标适配

事实：目标关键函数存在 LTO 后缀，源码缓存逻辑可找到大部分目标入口；`selinux_policy_commit` 在目标符号表中不存在，不能继续把它作为必需 hook。目标有 `context_struct_compute_av.llvm...`，源码当前按 6 参数 hook；目标入口机器码显示 `x0` 为 policydb、`x1/x2` 为上下文、`w3` 为 class，后续参数需按目标完整 ABI 证据核对。

待办：

- [ ] 把必需 hook 与可选 hook 分开；目标不存在的 `selinux_policy_commit` 不得导致功能状态误判。
- [ ] 对 `selinux_setprocattr`、`sel_write_context`、`sel_write_access` 使用目标 LTO 主函数入口，排除 `.cfi_jt` 跳板。
- [ ] 核对 `context_struct_compute_av` 的目标完整参数数量及 hook wrapper ABI；如无法证明 6 参数完整匹配，禁止安装该 hook，改由已证实的调用路径提供降级。
- [ ] 记录每个 hook 的成功/失败状态和原因，避免只看到 KPM 加载成功。
- [ ] 处理源码 `exit_()` 中已明确承认的 fake page 释放后引用风险：status 文件和 mmap 可能继续持有 page；必须先确定对象持有、在途回调和释放契约，不能直接释放。源码此处为 1725–1742 行；独立复核前不建议对设备执行卸载测试。

验证：

- 目标镜像离线符号和反汇编逐项复核。
- 构建后静态扫描 hook 参数、导入和失败清理路径。
- 真机日志确认实际安装的 hook 数量与目标入口地址类型。

收益/成本：收益中高；成本中。

## 验证要求

1. 只使用用户指定的目标镜像进行离线分析；不对 `kernel_img/` 中其他镜像运行全量推导。
2. 修改后先进行探索构建，再按仓库流程从冻结提交运行候选构建；不覆盖已有产物。
3. Developer 报告必须绑定完整 commit、Build ID/instance_id、产物 SHA-256，并声明自检边界。
4. 交付前由 Auditor 独立重解析产物、检查 hook ABI、边界和生命周期；由 Tester 在真机只测一个变体，并记录 status read/mmap、access/context、procattr 和模块存活判据。
5. 真机若无响应或出现崩溃特征，立即停止重试并按仓库升级流程保留现场。
