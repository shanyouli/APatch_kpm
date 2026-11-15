# 上游来源快照

`nomount/` 是由当前主仓库直接跟踪的普通源码目录，不再是 Git 子模块。保留原路径以维持源码、许可证和测试引用。

初始导入来自 `maxsteeel/nomount` 的 `bf1847f98fed382369c43bfd652cd93774b9b8e3`（v2.2.0），54 个原版文件逐字节保留。机器可读来源见 [SOURCE.json](SOURCE.json)，许可证与适用范围见 [UPSTREAM.md](../UPSTREAM.md)。

配套 ZIP 的用户态工具、WebUI、路径脚本和许可证从主仓库的同一冻结提交读取，输入哈希写入 ZIP 清单。清单中的 `upstream_commit` 表示初始上游来源；实际构建身份以主仓库的 `source_commit` 和逐文件指纹为准。生成副本的适配仍在打包器及 `module/webui-rules.js` 中维护。

历史子模块构建仍按其原提交中的声明与 gitlink 核验，不改写旧记录。
