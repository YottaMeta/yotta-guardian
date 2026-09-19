# 更新日志

## v0.1.4 (2026-09-19)

版本对齐维护：修复历史发布元数据与包内版本不一致；无功能变更。

## v0.1.3 (2026-09-13)

**P0-4.3 元盾 before_tool 试点**：

- 新增 `skill-manifest.json`，声明 `before_tool` / `guard_check` / `fallback: explicit-unverified`。
- 发布工作流 `.github/workflows/publish.yml` 纳入版本库，标签推送可触发 GitHub Actions。
- Codex 该事件为 `native-audit`：危险调用评估失败时只能审计并触发一次纠偏，不宣称动作前硬拦截。
- 元阁适配器回归验证 `native-audit` 结果、纠偏信号与审计证据写入。
- 补充使用范围、授权与法律红线声明，明确本技能不是操作系统沙箱，也不替代宿主权限控制与人工决策。

## v0.1.2 (2026-08-29)

- 安装方式统一为四方式（对齐发布规范 §3.3.1）：方式一 `npx -y @yottameta/yotta-guardian --agent <name>` / `--dir <dir>`（推荐，走 npm 源）；方式二 `git clone https://github.com/YottaMeta/yotta-guardian.git`；方式三 GitHub Download ZIP；方式四 `bash install.sh --agent/--dir/--list`。移除 `npx skills` 与 `-g` 推荐；中英双 README 安装节同步。
- 版本对齐：package.json / SKILL.md / CHANGELOG / 引擎 VERSION / 测试断言 / README 锚点 = 0.1.2。
- 无功能变更（仅文档与版本同步）。

## v0.1.1 (2026-08-28)

中英双语 README 对齐（英文门面 + 中文全档）：

- **README.md 改为英文**：作为 GitHub / npm / ClawHub 首页的英文门面（翻译 + 精简，覆盖定位 / 核心价值 / 命令 / 快速使用 / 安装 / 使用示例 / 边界 / 开发校验全流程）。
- **新增 README.zh-CN.md**：原中文完整主文档整体平移，顶部加语言切换链接。
- **修复代码围栏**：README 中 `_BT_`bash / `_BT_` 占位符全部改为标准 ```bash / ```（Markdown 渲染修复）。
- **package.json**：description 改英文；files 加 README.zh-CN.md；版本 0.1.0 → 0.1.1。
- 版本四处对齐：package.json / SKILL frontmatter / 引擎 VERSION / 文档。
- 边界（B 方案）：references / CHANGELOG / 测试注释不翻译；SKILL 触发描述保持中文。

## v0.1.0 (2026-08-26)

YottaMeta 自有实现首版（护栏/拦截方向参考开源社区同类技能思路，已完全重写，零依赖）：

- **零依赖自研引擎**（scripts/yotta_guardian.py，Python 3.8+ 标准库）：确定性规则引擎 + 可插拔意图验证，对 exec / write / edit / read / run / shell 工具调用做安全评估。
- **四层规则**：文本模式（下载即执行 / 编码执行 / 反向 shell / 系统文件追加）+ argv 级动词/目标分析（rm / dd / mkfs / chmod / chown / 提权 / 防火墙 / 服务 / 持久化 / 反向 shell）+ 敏感路径（/etc 核心文件、/boot、/dev、SSH 授权、Windows 系统目录与 hosts、注册表启动项等）+ 写入内容（私钥 / 密钥令牌）。
- **三档策略**：default（拒绝 high+）/ strict（拒绝 medium+）/ loose（仅拒绝 critical）；放行规则（--allow / --allow-path）可降级 high，critical 不可覆盖。
- **可插拔意图验证（不绑模型）**：默认零依赖；--heuristic 内置本地启发式；--verifier / 配置文件外接任意验证器（stdin/stdout JSON 协议）。
- **审计**：JSONL 审计日志 + audit 子命令（--tail / --denied / --since / --tool / --json）。
- **输出**：文本 / JSON（stdout 纯净）/ Markdown 报告；--batch 批量预检。
- **测试**：scripts/test_yotta_guardian.py 60 项全绿（命令/路径/内容/策略/放行/批量/JSON/报告/审计/验证器/配置/GBK 控制台）。
- **文档**：SKILL.md / README.md / references（rules / policies / intent-verifier）/ assets/banner.png。
- 版权：YottaMeta 纯自有 MIT + NOTICE 品牌声明。
