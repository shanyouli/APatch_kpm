# cgroupv2_freeze
## 模块作用
为低版本内核添加 cgroup.freeze

## 当前源码调整（未发布）

针对 Android 13 的厂商 4.14 内核，修复了一批可由只读环境信息确认的兼容阻塞：

- 在原生 `cgroup_mutex` 下遍历默认层级，给**已有分组**注册真实 `cgroup.freeze`；新建分组跟随原生基准文件回调注册。冲突在创建前拒绝，创建/属主设置失败回滚，不靠脚本生成普通文件。
- 注册字段与共同表布局已对指定 `miuiportspatched.img` 机器码自检：包括 cgroup.kn、CSS flags、cftype 步长；该镜像版本为 `4.14.186-perf-ga368196f0bd0`，不外推其它厂商编译形态。
- 冻结/解冻的 jobctl 修改使用原生 `lock_task_sighand` 与 siglock；冻结等待改在原生 `get_signal` 处理之后，保留致命/停止信号处理，醒来仍被冻结时让原生返回路径重新检查。
- 模块自有符号和布局识别锚点统一使用当前 KernelPatch 的后缀查询，支持 `$hash` 名称；不硬编码厂商哈希。后缀查询依赖运行端 KP 的 `cfi_bypass` 与符号遍历支持，找不到必要符号时停止初始化。
- 检查 SDK 函数指针及 `init_css_set`，避免缺失依赖后继续读取。修正固定窗口的回看/前瞻越界，区分合法的 `task_struct.state` 零偏移与未取得状态。
- 移除 `css_set.dfl_cgrp = 0x48` 的默认猜值；既有自引用识别不成功即失败。依赖该默认值的旧目标不再默默继续，需补目标布局证据。
- hook 安装失败时按安装记录逆序撤销本模块回调，不清除其他模块的 hook。
- 延迟初始化使用 `/system/bin/sh`，传播进程错误；复用 `/sys/fs/cgroup` 已有层级，不自动卸载、重挂载，也不递归改变 UID/PID 子树权限。
- 分别初始化 `frozen`、`unfrozen`；写入前确认内核已经提供 `cgroup.freeze` 和 `cgroup.procs`。目录存在但接口缺失时明确失败，不创建普通文件冒充接口。
- 控制应答只复制已初始化的固定字符串，检查用户缓冲区容量与拷贝结果，避免原有栈缓冲区尾部泄露。
- Makefile 补齐头文件依赖与内核态寄存器/编译器辅助调用约束。

**这不是实机通过或可交付声明。** 本轮已经实现已有分组回填及未来分组注册，并直接执行生产偏移代码核对指定镜像；没有加载到手机。原实现的全局 SELinux 临时切换、退出时 cftype 注销/在途回调同步仍未解决，不能安全宣称支持热卸载。完整层级冻结语义和 `cgroup.events` 的 frozen 完成通知也没有覆盖。当前注册要求 cgroup 已初始化；`load-file` 事件现在同样执行内核回填，仅仍不安装旧用户态延迟脚本 hook。

无须工具链的自检：

```bash
python3 cgroupv2_freeze/tests/test_source_contract.py
```

该自检只检查源码保护条件与隔离目录中的初始化脚本分支；不调用编译器、ADB、真实挂载或 chown，不代替偏移回归或独立审计。另有 `tests/target_offsets_host.c` 直接执行生产推导代码，以及 `tests/registration_host.c` 的原生注册接口夹具；它们需要本地 Clang，可验证选定目标窗口与注册算法，但不能证明内核并发和设备运行。

局部探索已用本机 Clang 生成 release/debug AArch64 ELF 对象；没有执行 Makefile 的完整 KPM 链接，没有登记候选，也没有加载到设备。

## 更新记录
### 1.0.12
适配更多内核
### 1.0.11
适配更多内核<br />
优化挂载脚本
### 1.0.10
优化 `MIUI` 内核
### 1.0.9
v2 检测函数由 `do_freezer_trap` 改为 `cgroup_freeze_write`
### 1.0.8
修复冻结失效
### 1.0.7
临时 hook `call_usermodehelper_exec`
### 1.0.6
为高版本内核禁用 `CONFIG_STATIC_USERMODEHELPER`
### 1.0.5
补全uid模式<br />
不再需要附加模块
### 1.0.4
使用其他方式替代所有内核版本判断条件<br />
变更 task_struct->jobctl 获取方式
### 1.0.3
支持 4.19
### 1.0.2
支持 4.9
### 1.0.1
不再修改内核配置文件
