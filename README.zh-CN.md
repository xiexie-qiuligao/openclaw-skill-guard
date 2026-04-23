# openclaw-skill-guard

[English README](./README.md)

**面向 OpenClaw Skills 的安全验证器。**

`openclaw-skill-guard` 是一个面向 Windows 交付的 Rust verifier，用于在发布或审查前扫描 `SKILL.md`、skill 目录、skills 根目录或更大工作区。它不是通用漏洞扫描器，也不是 exploit runner；它的目标是基于可见证据回答一个更实际的问题：这个 skill 在 OpenClaw 语境下是否可能形成真实攻击路径，以及结论背后的证据是什么。

## 交付面

- GUI
  - 当前主产品界面，适合日常审查、结果阅读和 JSON 导出
- CLI
  - 面向自动化、流水线和高级用户的入口

GUI 与 CLI 复用同一条 Rust core 扫描链，不引入第二套分析逻辑。

## 当前能力

- baseline dangerous-pattern scanning
- structured OpenClaw context extraction
- frontmatter / `metadata.openclaw` parsing
- install-chain analysis
- dependency audit
- invocation-policy analysis
- tool reachability
- secret reachability
- URL / API classification
- source / domain reputation hints
- prompt / instruction analysis
- corpus-backed threat analyzer
- corpus-backed sensitive analyzer
- attack-path reasoning
- compound scoring
- consequence model
- guarded runtime validation
- suppression / audit support
- canonical JSON report
- SARIF / Markdown / HTML 派生输出

## 快速开始

构建 CLI 与 GUI：

```powershell
cargo build --release -p openclaw-skill-guard-cli -p openclaw-skill-guard-gui
```

启动 GUI：

```powershell
cargo run -p openclaw-skill-guard-gui
```

GUI 主流程：

1. 选择 `SKILL.md` 或目录。
2. 直接点击“开始扫描”。
3. 只有在需要时才展开高级选项，配置 runtime manifest、suppression 或 validation mode。
4. 默认先阅读“总览”页，再进入发现项、攻击路径、上下文、运行时验证和审计页。
5. 按需导出 canonical JSON 报告。

CLI 仍可用于自动化：

```powershell
cargo run -p openclaw-skill-guard-cli -- scan .\fixtures\v2\report-demo --format json
```

## GUI 形态

GUI 现在不再是简单的 CLI 参数面板，而是默认中文、总览优先的正式桌面产品界面。当前重点包括：

- 主扫描流程收敛为“选目标 -> 开始扫描 -> 看总览”
- 高级项可折叠，不再默认把全部技术参数堆在首页
- 结果区默认先展示总览，而不是空白页或原始 JSON
- Findings / Paths / Context / Validation / Audit 均按阅读体验重排
- Findings / Paths 支持轻量筛选
- Findings / Paths / Audit 之间已有基础联动跳转
- v2 新增 summary 会在 GUI 中清楚展示
- 仍然复用 canonical report 主链，并支持 JSON / SARIF / Markdown / HTML 导出

## GUI 截图

最终交付附带了少量展示截图，位于 `docs/gui-screenshots/`：

- `gui-home-empty.png`
- `gui-overview-demo.png`
- `gui-validation-demo.png`

预览：

![GUI 空状态](./docs/gui-screenshots/gui-home-empty.png)
![GUI 总览](./docs/gui-screenshots/gui-overview-demo.png)
![GUI 运行时验证](./docs/gui-screenshots/gui-validation-demo.png)

## 报告契约

JSON 仍然是唯一 canonical report。SARIF、Markdown、HTML 都是从同一个 `ScanReport` 派生出来的输出，而不是第二套协议。

v2 关键 section 包括：

- `findings`
- `context_analysis`
- `attack_paths`
- `corpus_assets_used`
- `dependency_audit_summary`
- `api_classification_summary`
- `source_reputation_summary`
- `external_references`
- `scoring_summary`
- `consequence_summary`
- `validation_*`
- `audit_summary`

更多说明见：

- [report.schema.json](./schemas/report.schema.json)
- [reporting.md](./docs/reporting.md)
- [examples/reports/README.md](./examples/reports/README.md)

## 安全边界

`openclaw-skill-guard` 是 verifier，不是 exploit runner。

- 不主动执行危险 payload
- runtime validation 保持 guarded、non-executing
- reputation 只做本地、可解释提示，不伪装成在线信誉真相
- suppression 保持 audit 可见性，不做静默隐藏
