# Agent Skill Guard

**中文优先的 Agent Skill / Tool / MCP 安全验证器。GUI 是主入口，CLI 适合自动化和高级用户。**

Agent Skill Guard 用于在安装、发布或审查 Agent skill、OpenClaw Skill、MCP 配置、prompt package 或规则文件之前做本地安全验证。它会分析 `SKILL.md`、skill 目录、skills 根目录，也支持直接粘贴 HTTPS skill 链接进行扫描。报告会解释安装链、权限/能力声明、环境变量、外部链接、提示词、间接指令、攻击路径、运行时约束和组合风险。

它不是 exploit runner，不会执行远程代码、安装脚本或危险 payload。它的定位是 verifier / guard：用静态证据、结构化上下文和 guarded runtime validation 帮助你判断一个 skill 是否值得信任、哪里需要人工复核、哪些风险应该阻断。

## 下载和使用 GUI

普通用户建议直接下载 Windows GUI 压缩包：

1. 打开仓库右侧的 **Releases**。
2. 下载 `agent-skill-guard-gui-windows.zip`。
3. 解压后运行 `agent-skill-guard-gui.exe`。
4. 如果需要自动化扫描，同一个压缩包内也提供 `agent-skill-guard.exe` CLI。

GUI 使用流程：

1. 输入或选择一个 `SKILL.md`、skill 目录、skills 根目录，或粘贴 HTTPS skill 链接。
2. 点击“开始扫描”。
3. 先看“总览”，再按需查看“发现项”“攻击路径”“上下文”“运行时验证”“审计”。
4. 需要交付或存档时，导出 JSON、SARIF、Markdown 或 HTML。

支持的远程输入包括 GitHub repo / tree / blob / raw `SKILL.md`、直接 `.zip` 下载链接，以及普通 `https://.../SKILL.md` 文本链接。远程内容只会下载到安全临时目录后静态扫描，不会执行。

## 能检查什么

- `SKILL.md`、frontmatter、`metadata.openclaw`
- OpenClaw config / control-plane 风险，例如 `env`、`apiKey`、sandbox disabled、危险配置绑定
- capability / permission manifest 与实际信号不一致
- companion docs / indirect instruction / doc poisoning
- install-chain 风险，例如远程脚本、依赖拉取、弱固定版本
- invocation policy、tool reachability、secret reachability
- prompt injection、precedence / shadowing、attack path、compound scoring
- host-vs-sandbox consequence modeling 与 guarded runtime validation
- dependency audit、URL / API classification、source / domain reputation
- 不可信输入、敏感数据面与外联/执行能力形成的组合风险
- 隐藏指令 / Trojan Source / schema 投毒 / Markdown 链接误导
- “声明 vs 实际证据”对照：自称只读、实际权限、安装来源、配置绑定是否一致
- SKILL.md SHA-256 完整性快照和当前扫描范围内的本地 Agent / MCP 配置引用
- 通用 Agent package 生态解析、MCP / Tool Schema 静态审计、AI BOM
- corpus-backed threat / sensitive analyzers
- suppression / audit

## 报告格式

JSON 是 canonical report，也是唯一机器契约。其他格式都从同一份报告派生：

- JSON：完整机器可读报告
- SARIF：适合安全工具和代码扫描平台
- Markdown：适合人工审查、issue、PR 和交付说明
- HTML：适合直接打开阅读

面向人的标题、解释、建议和摘要默认中文优先；JSON / SARIF 字段名保持稳定，便于自动化集成。

安全报告会尽量使用相对路径或脱敏路径展示扫描目标，避免把本机目录、临时目录或用户信息写进对外报告。

## CLI 使用

构建 GUI 和 CLI：

```powershell
cargo build --release -p agent-skill-guard-cli -p agent-skill-guard-gui
```

产物：

```text
target\release\agent-skill-guard-gui.exe
target\release\agent-skill-guard.exe
```

本地扫描：

```powershell
.\target\release\agent-skill-guard.exe scan .\fixtures\v2\report-demo --format markdown
```

链接扫描：

```powershell
.\target\release\agent-skill-guard.exe scan https://github.com/example/example-skill --format html
```

策略与 CI：

```powershell
.\target\release\agent-skill-guard.exe scan <本地路径或HTTPS链接> --config .\.openclaw-guard.yml --ci
.\target\release\agent-skill-guard.exe scan <本地路径或HTTPS链接> --no-network
.\target\release\agent-skill-guard.exe scan <本地路径或HTTPS链接> --agent-ecosystem
```

`.openclaw-guard.yml` 可配置语言、CI 阻断策略、最低分数、禁用规则、远程输入开关、远程下载大小和归档文件数量限制。

## 开发验证

```powershell
cargo test
```

## 安全边界

- 不执行远程 skill、安装脚本或危险 payload
- 不做在线信誉平台或云端判定
- 不把本地 hint 伪装成绝对可信结论
- runtime validation 保持 guarded、non-executing
- suppression 必须可审计，不会静默隐藏风险

## English Summary

Agent Skill Guard is a Chinese-first, Windows-friendly Rust verifier for reviewing Agent skills, OpenClaw Skills, MCP configs, prompt packages, and tool rules before installation, release, or audit. The GUI is the primary product surface; the CLI is intended for automation and advanced workflows.

It scans local `SKILL.md` files, skill directories, skill roots, and HTTPS skill links. Remote content is fetched into a safe temporary location and scanned statically; the tool does not execute remote code, install dependencies, or act as an exploit runner.

The canonical JSON report remains the source of truth. SARIF, Markdown, and HTML are derived exports. Human-facing summaries are Chinese-first, while machine-readable field names remain stable.
