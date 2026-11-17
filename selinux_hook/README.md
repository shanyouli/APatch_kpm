# SELinux MAF 目标适配（1.1.9.2，探索版本）

本模块基于用户提供的 `selinux_maf_fork-main-1794886208355.zip` 修改。当前只针对 `folk_patched_115404_0.13.9_mivk.img` 的 `4.14.186-perf-ga368196f0bd0` 做了离线分析与构建自检，尚未取得独立审计或实机有效性结论。

目标 boot SHA-256：`30325db5c2e35a637e4afb77bd411295e9cd916eee0b05f6ee939d950c1de335`。

## 改动

目标内核将 status page 分配内联进 `sel_open_handle_status()`。原版只 hook 独立的 `selinux_kernel_status_page()`，覆盖不到该路径。此版在 open 成功后，为 UID >= 10000 的调用替换该文件的 status page。read 和 mmap 使用同一页；在 open 前已持有的文件描述符不会被追溯替换。

写 `file->private_data` 前要求目标 read/mmap 入口、open 的参数保存与写入指令都匹配已核对的窗口，并检查当前页大小为 4 KiB。匹配失败时关闭这一路并保留诊断；不按版本号填入字段偏移。本适配不是任意 4.14 厂商内核通用实现。

- dynamic 版从已接受的目标读取指令中取得偏移。
- baselines 版使用 `.data.re_offsets` 配置表和配套 JSON，但仍核对目标窗口，当前只接受已确认的 `+0xc8`。JSON 可修改不代表其它布局已获支持。
- hook 注册成功后才登记；失败会返回错误并清理已登记 hook。
- 保留原版 `mode` 命令，增加 `status` 命令。策略缺失时输出 `POLICYDB_REQ`，必要 hook 或 status 路径缺失时输出原协议拼写 `UNSUPORRT`。
- `status` 输出 `policy_ready`、`policy_errno`（正 errno）、`status_open`、`queries`、`compute`、`string`、`hooks`。其中 `policy_errno=0` 表示策略解析成功。
- 捕获策略载荷时使用 nofault 读取；无法读取时拒绝捕获。
- 必须解析出成对的 scope 锁函数；不再允许共享 scope 数组无锁运行。
- status backing page 退出后保留到重启，避免已打开文件或 mmap 引用已释放页面。每次成功加载/卸载可能额外保留一页内存。

## 构建

需要支持 AArch64 ELF 的 Clang、ELF 链接器、Python 3 和当前 KernelPatch SDK。默认使用 Clang 编译、Zig 链接，也可通过命令行设置 `CC`、`LD`。GitHub Actions 使用 `CC="clang --target=aarch64-linux-gnu" LD=ld.lld`，无需安装 Zig。Makefile 只面向当前 SDK，不包含旧 KP 兼容分支。

```sh
make -C selinux_hook all OUT_DIR=../local/selinux-maf-build-new
```

输出目录必须是新的目录，已有同名 KPM 时拒绝覆盖。两份普通产物共用同一模块管理名称，每次只能选择一种。

```text
selinux_MAF_fork_1.1.9.2.kpm
selinux_MAF_fork_1.1.9.2_baselines.kpm
selinux_MAF_fork_1.1.9.2_baselines.kpm.json
```

## 自检

```sh
python3 selinux_hook/tools/test_target.py
uv run --with pyelftools --with capstone python selinux_hook/tools/check_artifact.py <dynamic.kpm> <baselines.kpm>
```

`test_target.py` 抽取生产函数进行 ASan/UBSan 宿主测试，覆盖布局冲突拒绝、缺符号、nofault 失败、UID 分流、open 失败、无策略/策略解析失败、mode 状态和字符串边界。可另传 `--image <Image> --symbols <symbols.json>` 对照目标指令；符号清单格式为 `[相对 Image 偏移, 类型字符, 名称]` 的数组。

这些测试不运行真实 hook，不证明 CFI、锁、真实 policydb、启动顺序、卸载同步或检测应用结果。`check_artifact.py` 核对 ELF 类型、入口节、裸 libc 导入及实际机器码中的 SIMD/FP/x18；完整运行端导出匹配仍需审计。

## 当前边界

- 这是未冻结源码的探索构建，不是仓库候选交接或签名交付；没有正式 Build ID/instance_id。
- 政策来源仍沿用原版：策略文件或首次成功 `security_load_policy` 的载荷。启动阶段没捕获到干净策略，或载荷本来已修改时，不能声称恢复了原厂策略。镜像本身不足以证明启动时的策略内容。
- 仍保留原版 status 字段值和 access seqno 处理；两类序列字段语义不同，未宣称检测器契约已被验证。
- 保留 status 页解决的是已发布页面的释放后引用问题；KernelPatch 的 hook 撤销/在途回调同步和 policydb 释放仍须独立审计。不要据此推断热卸载已经安全。
- 尚未操作设备，也未改写或重打包 boot。实机结果需由 Tester 绑定精确字节验证。
