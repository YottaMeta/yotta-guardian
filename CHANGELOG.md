# 更新日志

## v0.1.1 (2026-08-28)

中英双语 README 对齐（老张拍板「英文门面 + 中文全档」）：

- **README.md 改为英文**：作为 GitHub / npm / ClawHub 首页的英文门面（翻译 + 精简，覆盖定位 / 核心价值 / 命令 / 快速使用 / 安装 / 使用示例 / 边界 / 开发校验全流程）。
- **新增 README.zh-CN.md**：原中文完整主文档整体平移，顶部加语言切换链接。
- **修复代码围栏**：README 中 `_BT_`bash / `_BT_` 占位符全部改为标准 ```bash / ```（Markdown 渲染修复）。
- **package.json**：description 改英文；files 加 README.zh-CN.md；版本 0.1.0 → 0.1.1。
- 版本四处对齐：package.json / SKILL frontmatter / 引擎 VERSION / 文档。
- 边界（B 方案）：references / CHANGELOG / 测试注释不翻译；SKILL 触发描述保持中文。

## v0.1.0 (2026-08-26)

YottaMeta 自有实现首版（护栏/拦截方向参考开源社区 safe-guardian 类技能思路，已完全重写，零依赖、无上游代码）：

- **零依赖自研引擎**（scripts/yotta_guardian.py，Python 3.8+ 标准库）：确定性规则引擎 + 可插拔意图验证，对 exec / write / edit / read / run / shell 工具调用做安全评估。
- **四层规则**：文本模式（下载即执行 / 编码执行 / 反向 shell / 系统文件追加）+ argv 级动词/目标分析（rm / dd / mkfs / chmod / chown / 提权 / 防火墙 / 服务 / 持久化 / 反向 shell）+ 敏感路径（/etc 核心文件、/boot、/dev、SSH 授权、Windows 系统目录与 hosts、注册表启动项等）+ 写入内容（私钥 / 密钥令牌）。
- **三档策略**：default（拒绝 high+）/ strict（拒绝 medium+）/ loose（仅拒绝 critical）；放行规则（--allow / --allow-path）可降级 high，critical 不可覆盖。
- **可插拔意图验证（不绑模型）**：默认零依赖；--heuristic 内置本地启发式；--verifier / 配置文件外接任意验证器（stdin/stdout JSON 协议）。
- **审计**：JSONL 审计日志 + audit 子命令（--tail / --denied / --since / --tool / --json）。
- **输出**：文本 / JSON（stdout 纯净）/ Markdown 报告；--batch 批量预检。
- **测试**：scripts/test_yotta_guardian.py 60 项全绿（命令/路径/内容/策略/放行/批量/JSON/报告/审计/验证器/配置/GBK 控制台）。
- **文档**：SKILL.md / README.md / references（rules / policies / intent-verifier）/ assets/banner.png。
- 版权：YottaMeta 纯自有 MIT + NOTICE 品牌声明；README 一行上游致谢。
