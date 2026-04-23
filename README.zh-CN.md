# Standalone OpenClaw Skill Guard

[English README](./README.md)

**面向 OpenClaw Skill 生态的命令行安全验证器。**
**An OpenClaw-aware verifier for CLI-first security review.**

Standalone OpenClaw Skill Guard 是一个基于 Rust、对 Windows 友好的 OpenClaw-aware skill verifier。它可以扫描单个 `SKILL.md`、整个 skill 目录、skills 根目录，甚至更大的工作区，并回答一个更贴近真实发布决策的问题：**在当前 OpenClaw 运行语义和可见运行时条件下，这个 skill 是否可能形成可信的攻击路径？为什么？**

它不是通用 markdown 扫描器，也不是只靠少量危险词规则的轻量检查器。这个项目把 OpenClaw 结构化上下文、攻击路径推理、后果建模和受控运行时验证组合起来，帮助使用者判断问题是否真的可达、是否会突破策略边界，以及是否值得阻断发布。

这里强调 OpenClaw-aware，不是为了换一个说法，而是因为真实风险会受到这些语义影响：`metadata.openclaw`、调用策略、安装路径与安装器路径的不对称、工具与密钥可达性、precedence 和 shadowing、权限边界，以及 sandbox 限制。这个项目的定位，就是在不执行危险 payload 的前提下，对这类风险做可解释验证。

## 产品定位

- 这是一个什么工具
  - 一个面向 OpenClaw Skill 仓库审查和发布前检查的 CLI-first verifier
- 它不是什么
  - 不是 generic scanner，不是 exploit runner，也不是动态恶意样本执行器
- 它交付什么
  - 以 JSON 为 canonical report 的结构化审计结果，可用于人工复核、流水线接入、样例演示和发布验收
- 它的独特价值
  - 不只看“有没有危险词”，而是结合 OpenClaw 运行语义，判断“能不能形成真实攻击链”

## 核心能力

- 基线扫描
  - 继承并稳定化危险模式规则，用于提供初始风险线索
- OpenClaw 结构化上下文分析
  - `SKILL.md` frontmatter 解析
  - `metadata.openclaw` 标准化
  - invocation policy 分析
- 安装链、可达性与优先级分析
  - install chain 提取
  - tool reachability
  - secret reachability
  - precedence / shadowing 分析
- 指令与提示风险分析
  - instruction extraction
  - prompt injection
  - indirect instruction
  - tool / secret coercion
- 攻击路径推理
  - toxic-flow attack paths
  - compound risk rules
  - path-aware scoring 与 verdict
- 运行时约束下的结果收束
  - host vs sandbox consequence model
  - runtime manifest 导入
  - guarded validation hooks
  - sandbox-backed guarded validator checks
  - controlled runtime refinement
- 审计与误报控制
  - provenance notes
  - confidence shaping
  - suppression matching
  - audit reporting

## 为什么它不是 generic scanner

普通扫描器通常只能回答“文件里有没有可疑片段”。这个项目会继续往前推一步，结合 OpenClaw 自身语义回答：

**这个 skill 在真实 OpenClaw 运行条件下，是否可能形成一条可信的攻击路径？**

它关注的是 generic scanner 往往缺失的内容：

- `metadata.openclaw`
- `command-dispatch` 与直接工具权限
- `disable-model-invocation` 与 `user-invocable`
- install path 与 installer path 的不对称
- tool / secret reachability
- precedence、shadowing、trusted-name collision
- runtime permission 与 environment constraints

## CLI / EXE 使用方式

### 本地构建

```powershell
cargo build
```

### 构建 Windows EXE

```powershell
cargo build --release
```

生成的可执行文件为：

```text
target\release\openclaw-skill-guard.exe
```

### 查看 CLI 帮助

```powershell
cargo run -p openclaw-skill-guard-cli -- --help
```

### 扫描单个 `SKILL.md`

```powershell
cargo run -p openclaw-skill-guard-cli -- scan .\fixtures\v1\prompt-risk\SKILL.md --format json
```

### 扫描整个 skill 目录

```powershell
cargo run -p openclaw-skill-guard-cli -- scan .\fixtures\v1\install-risk --format json
```

### 搭配 runtime manifest 做受控验证

```powershell
cargo run -p openclaw-skill-guard-cli -- scan .\fixtures\v1\runtime-refinement\SKILL.md --format json --runtime-manifest .\fixtures\v1\runtime-refinement\runtime-sandbox.json --validation-mode guarded
```

### 搭配 suppression 文件

```powershell
cargo run -p openclaw-skill-guard-cli -- scan .\fixtures\v1\suppression-audit\SKILL.md --format json --suppressions .\fixtures\v1\suppression-audit\suppressions.json
```

### 直接运行 Windows EXE

```powershell
.\target\release\openclaw-skill-guard.exe scan .\fixtures\v1\benign\SKILL.md --format json
.\target\release\openclaw-skill-guard.exe scan .\fixtures\v1\prompt-risk\SKILL.md --format json
```

## 报告怎么读

当前 v1 的 canonical output 是 `JSON`。如果你准备把它接入发布检查、人工复核或归档，这几个 section 最重要：

- `findings`
  - 单条问题，带证据、级别和修复方向
- `context_analysis`
  - 结构化 OpenClaw 上下文，包括 metadata、install chain、invocation、reachability、precedence、prompt 摘要等
- `attack_paths`
  - 由 findings 和上下文拼接出来的真实风险链
- `scoring_summary`
  - 基础分、复合加权、路径加权、置信度修正和最终分值
- `consequence_summary`
  - host 与 sandbox 下的影响差异
- `validation_*`
  - 验证计划、运行时事实、验证结果、路径状态和运行时分值修正
- `guarded_validation`
  - 受 sandbox 约束的能力与条件检查，用来收窄或确认路径，但不执行不可信内容
- `provenance_notes` / `confidence_notes`
  - 结论依据来自哪里，哪些部分仍有不确定性
- `suppression_matches` / `audit_summary`
  - 哪些结果被有意识地压制，但仍保留可审计痕迹
- `analysis_limitations`
  - 当前扫描仍然看不到、确认不了、或受作用域限制的部分

如果你要对接字段定义，可以继续看：

- [report.schema.json](./schemas/report.schema.json)
- [reporting.md](./docs/reporting.md)
- [runtime-manifest.md](./docs/runtime-manifest.md)
- [validation-adapter.md](./docs/validation-adapter.md)

## Windows EXE 交付方式

如果你要把它作为一个可直接分发的 Windows 命令行工具交付，最简路径是：

- 执行 `cargo build --release`
- 交付 `target\release\openclaw-skill-guard.exe`
- 同时附带 `README.md`、`README.zh-CN.md`、`CHANGELOG.md`、`schemas/report.schema.json` 和关键 `docs/` 文档
- 如果需要对外演示，可额外附带 `examples/` 与 `fixtures/`

更完整的打包说明见 [docs/packaging.md](./docs/packaging.md)。

## 误报控制与审计可见性

这个项目不会只靠关键词命中直接下结论。为了降低误报，它还会保留并利用：

- provenance notes，用来说明结论来自直接证据还是推断
- confidence shaping，用来区分“看到明确行为”和“由上下文推理得出”
- guarded runtime refinement，用来用安全方式确认能力边界和作用域
- 针对 localhost / RPC 工作流、引用示例、良性 `child_process` 文本、合法安装指导等场景的误报收束
- suppression 与 audit 输出，用来在保留痕迹的前提下接受人工例外

## 当前限制项

这个 release 明确区分以下几层能力：

- 静态结论
  - 基于仓库内容、metadata 和 attack-path 逻辑得出的判断
- runtime refinement
  - 基于 runtime manifest 或安全本地检查，对路径进行确认、收窄或阻断
- guarded validation
  - 在不运行不可信内容的前提下，检查能力、作用域和环境条件
- scope limitations
  - 由于根目录不可见、运行时事实不足、环境面未覆盖而保留的不确定性

当前版本刻意 **不会** 做这些事情：

- 执行 install chain 或危险 payload
- 运行任意 shell、PowerShell 或 `child_process`
- 主动拉取未知远程内容做验证
- 声称拥有完整的全局 precedence truth graph
- 接入 reputation、signing、SBOM 或 AI-BOM 验证
- 充当 exploit runner 或动态恶意代码沙箱

## 安全声明

这个项目的安全边界非常明确：它是 **verifier**，不是 exploit runner。

- 不主动执行危险 payload
- runtime validation 是 guarded、受控、可解释的
- runtime adapter 只做 manifest 导入、安全本地存在性检查、作用域校验和后果收束
- 高风险结论仍然需要有证据支撑，并在报告中保留审计轨迹

## 当前发布状态

当前仓库已经达到可发布的 `v1.0.0-rc1` 状态，适合作为 CLI-first、Windows-friendly 的公开仓库对外展示：

- 核心 verifier 已实现
- CLI 用法稳定，适合 v1 使用
- schema 和报告契约已文档化
- 示例与 demo 报告已附带
- Windows EXE 构建与入口已说明
- 根目录测试已通过

对外发布时可直接参考这些材料：

- [CHANGELOG.md](./CHANGELOG.md)
- [docs/packaging.md](./docs/packaging.md)
- [docs/release-ready.md](./docs/release-ready.md)
- [docs/github-release-kit.md](./docs/github-release-kit.md)
- [examples/reports](./examples/reports)

如果你需要看实现过程和架构背景，可以继续查看 [docs/progress.md](./docs/progress.md) 与 [docs/design.md](./docs/design.md)。
