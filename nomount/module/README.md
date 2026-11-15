# NoMount-kpm

NoMount 必装的配套 ZIP，负责加载普通模块的文件，并提供 WebUI。

1. 在 APatch 的内核模块页面「安装」或「嵌入」适合设备的 NoMount KPM，重启。
2. 安装 `NoMount-kpm.zip`，重启。

本次要用的 KPM 若已安装或嵌入并成功加载，可直接进行第 2 步。

在 APatch 中确认 NoMount 已加载，打开 NoMount 的 WebUI 查看状态和文件规则。

在「模块」页展开「当前挂载」，可搜索目标或来源路径，查看规则类型及 UID 作用范围。点击某条规则的「移除」并确认，仅撤销该条运行时规则；条目会保留「重新加载」按钮，可在当前 WebUI 会话内恢复。移除目录规则不会一起删除独立子规则。重启或重新加载整个模块可能恢复已移除规则，源文件不受影响。

「排除」按应用 UID 绕过 NoMount 规则，不删除挂载。应用已打开的文件和已有映射不会强制切换，修改后建议重新打开应用验证。

用户态工具和 WebUI 来自 maxsteeel/nomount（GPL-3），KPM 移植及配套改造由 Codex（OpenAI）完成，详见 [NOTICE.md](NOTICE.md)。
