# GitHub Release Kit

This file collects the copy needed to publish `v1.0.0-rc1` on GitHub without rewriting release text by hand.

## Repo description

OpenClaw-aware skill verifier for CLI-first security review, canonical JSON reporting, and guarded runtime validation.

## Suggested topics

- `openclaw`
- `security`
- `security-tools`
- `cli`
- `rust`
- `skill-verifier`
- `static-analysis`
- `runtime-validation`
- `json-report`
- `supply-chain-security`

## Short blurb

Standalone OpenClaw Skill Guard is a CLI-first verifier for reviewing OpenClaw skills before release. It combines structured OpenClaw context, attack-path reasoning, and guarded runtime validation to explain whether a skill can plausibly become a real attack chain, without executing dangerous payloads.

## 中文 short blurb

Standalone OpenClaw Skill Guard 是一个面向 OpenClaw Skill 发布前审查的 CLI-first verifier。它结合结构化上下文、攻击路径推理和 guarded runtime validation，帮助你判断一个 skill 是否可能形成真实攻击链，同时不执行危险 payload。

## Release title

`v1.0.0-rc1`

## Release body

### English

Standalone OpenClaw Skill Guard is an OpenClaw-aware skill verifier for CLI-first security review. It inspects `SKILL.md`, skill directories, skills roots, and broader workspaces, then explains whether a skill can plausibly form a real attack path under visible OpenClaw runtime conditions.

This release candidate includes baseline dangerous-pattern scanning, structured `SKILL.md` and `metadata.openclaw` parsing, install and invocation analysis, tool and secret reachability, precedence and shadowing analysis, instruction and prompt-risk analysis, attack-path reasoning, consequence modeling, provenance and confidence notes, suppression and audit output, and guarded runtime refinement through runtime manifests and sandbox-backed validator checks.

The release is delivered as a Rust CLI with canonical JSON reporting and a documented Windows EXE path. The primary public report contract is the JSON schema in `schemas/report.schema.json`, and the Windows-friendly release artifact is `target\release\openclaw-skill-guard.exe`.

Current limits remain intentional. `v1.0.0-rc1` is CLI-first, scope-aware, and non-executing: runtime validation is guarded, precedence truth is not globally omniscient, and reputation, signing, SBOM, AI-BOM, and GUI surfaces are out of scope for this release candidate.

Security boundary: this project is a verifier, not an exploit runner. It does not intentionally execute dangerous payloads, arbitrary install chains, unknown remote content, or untrusted shell workflows. Guarded validation is used only to refine reachability, capability, and consequence while preserving an auditable, evidence-driven report.

### 中文

Standalone OpenClaw Skill Guard 是一个面向 OpenClaw Skill 生态的 CLI-first 安全验证器。它可以检查单个 `SKILL.md`、skill 目录、skills 根目录以及更大的工作区，并结合可见的 OpenClaw 运行时条件，判断一个 skill 是否可能形成真实可达的攻击路径，并给出证据解释。

这个 release candidate 包含以下能力：基线危险模式扫描、`SKILL.md` 与 `metadata.openclaw` 的结构化解析、安装链与调用策略分析、工具与密钥可达性分析、precedence / shadowing 分析、指令与 prompt 风险分析、攻击路径推理、后果建模、provenance / confidence 说明、suppression / audit 输出，以及基于 runtime manifest 和 sandbox-backed validator checks 的 guarded runtime refinement。

本次交付形式是 Rust CLI，canonical output 为 JSON 报告，并已具备明确的 Windows EXE 交付路径。对外报告契约以 `schemas/report.schema.json` 为准，Windows 友好的可执行产物为 `target\release\openclaw-skill-guard.exe`。

当前限制项是有意保留的。`v1.0.0-rc1` 是一个 CLI-first、scope-aware、non-executing 的 release candidate：runtime validation 仍然是 guarded 的，precedence truth 不是全局全知的，reputation、signing、SBOM、AI-BOM 和 GUI 界面均不在本次发布范围内。

安全边界同样明确：这个项目是 verifier，不是 exploit runner。它不会主动执行危险 payload、任意 install chain、未知远程内容或不可信 shell 工作流。guarded validation 只用于收窄可达性、能力边界和后果判断，同时保留可审计、证据驱动的报告输出。
