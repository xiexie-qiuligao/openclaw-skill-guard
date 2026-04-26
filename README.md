# OpenClaw Skill Guard

**OpenClaw Skill 安全扫描器。GUI 是主入口，CLI 适合自动化。**

OpenClaw Skill Guard 用来在安装、发布或审查 OpenClaw Skill 之前做本地安全检查。它会读取 `SKILL.md`、skill 目录或 workspace，分析其中的安装命令、权限声明、环境变量、外部链接、提示词、间接指令、攻击路径和运行时约束，最后给出一个可解释的风险报告。

它不是 exploit runner，也不会主动执行危险 payload。它的定位是 verifier / guard：尽量用静态证据、结构化上下文和受保护的运行时信息，帮助你判断一个 skill 是否值得信任、哪里需要人工复核、哪些风险必须阻断。

## 下载 GUI

普通用户建议直接下载 Windows GUI 压缩包：

1. 打开仓库右侧的 **Releases**。
2. 下载 `openclaw-skill-guard-gui-windows.zip`。
3. 解压后运行 `openclaw-skill-guard-gui.exe`。

GUI 默认中文，适合日常使用。CLI 主要留给 CI、脚本和高级用户。

## GUI 怎么用

1. 打开 `openclaw-skill-guard-gui.exe`。
2. 选择一个 `SKILL.md` 文件，或选择一个 skill 目录。
3. 点击“开始扫描”。
4. 先看“总览”：这里会显示最终结论、分数、关键风险和建议。
5. 如果需要细看，再进入发现项、攻击路径、上下文、运行时验证、审计和原始 JSON。
6. 需要交付或存档时，可以导出 JSON、SARIF、Markdown 或 HTML。

## 能检查什么

- `SKILL.md`、frontmatter 和 `metadata.openclaw`
- 安装链风险，例如远程脚本、依赖拉取和弱固定版本
- invocation policy、tool reachability、secret reachability
- prompt injection、间接指令和 companion docs 风险
- attack path、compound scoring 和 consequence model
- OpenClaw config / control-plane 风险
- capability / permission manifest 与实际行为不一致
- source identity / repository / homepage / install source 不一致
- URL / API 分类、source / domain reputation hints
- corpus-backed threat / sensitive analyzer
- guarded runtime validation
- suppression / audit

## 报告格式

JSON 是唯一 canonical report。其他格式都从同一个报告派生：

- JSON：完整机器可读报告
- SARIF：适合安全工具和代码扫描平台
- Markdown：适合人工审查和 issue / PR 说明
- HTML：适合直接打开阅读

## 从源码构建

需要 Rust 工具链。

构建 GUI 和 CLI：

```powershell
cargo build --release -p openclaw-skill-guard-cli -p openclaw-skill-guard-gui
```

产物：

```text
target\release\openclaw-skill-guard-gui.exe
target\release\openclaw-skill-guard.exe
```

运行 GUI：

```powershell
.\target\release\openclaw-skill-guard-gui.exe
```

CLI 示例：

```powershell
.\target\release\openclaw-skill-guard.exe scan .\fixtures\v2\report-demo --format json
```

导出其他格式：

```powershell
.\target\release\openclaw-skill-guard.exe scan .\fixtures\v2\report-demo --format sarif
.\target\release\openclaw-skill-guard.exe scan .\fixtures\v2\report-demo --format markdown
.\target\release\openclaw-skill-guard.exe scan .\fixtures\v2\report-demo --format html
```

## 开发验证

```powershell
cargo test
```

## 安全边界

- 不主动执行危险 payload。
- 不做在线信誉平台。
- 不把本地 hint 伪装成绝对可信结论。
- runtime validation 保持 guarded、non-executing。
- suppression 必须可审计，不会静默隐藏风险。

## English Summary

OpenClaw Skill Guard is a Windows-friendly Rust verifier for reviewing OpenClaw Skills before installation, release, or audit. The GUI is the primary product surface, while the CLI is intended for automation and advanced workflows.

It scans `SKILL.md`, skill directories, and workspaces for install-chain risk, prompt and indirect-instruction risk, tool and secret reachability, OpenClaw config/control-plane exposure, capability mismatch, source identity mismatch, dependency risk, URL/API risk, attack paths, consequence modeling, guarded runtime validation, and audit-visible suppressions.

JSON is the canonical report format. SARIF, Markdown, and HTML are derived outputs.
