use std::fmt::Debug;

use crate::types::{Finding, FindingConfidence, FindingSeverity, ScanReport, Verdict};

pub fn zh_text(input: &str) -> String {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return "无可展示内容。".to_string();
    }
    let exact = match trimmed {
        "No findings." => Some("未发现需要展示的风险项。"),
        "No attack paths." => Some("未形成达到阈值的攻击路径。"),
        "No external references." => Some("未发现外部引用。"),
        "No dependency findings." => Some("未发现依赖审计问题。"),
        "No supported dependency manifests were discovered." => {
            Some("未发现当前版本支持的依赖清单文件。")
        }
        "No attack path met the current evidence threshold, but isolated findings may still require review." => {
            Some("没有攻击路径达到当前证据阈值，但孤立发现项仍建议复核。")
        }
        "No inline sensitive-data corpus entries produced independent findings after overlap control." => {
            Some("敏感数据模式库在重叠控制后未产生独立发现项。")
        }
        "No source or domain reputation hints were generated." => {
            Some("未生成来源或域名信誉提示。")
        }
        "No OpenClaw config/control-plane audit findings were generated from local evidence." => {
            Some("本地证据未生成 OpenClaw 配置 / 控制面发现项。")
        }
        "Capability manifest found no declared or inferred capability entries." => {
            Some("能力视图未发现声明或推断出的能力条目。")
        }
        "No companion documents were identified in the current scan scope." => {
            Some("当前扫描范围未发现配套文档。")
        }
        "No SKILL.md file was parsed from the current scan scope." => {
            Some("当前扫描范围未解析到 SKILL.md。")
        }
        "No skill metadata was available in the current scan scope." => {
            Some("当前扫描范围没有可用的 skill 元数据。")
        }
        "No install metadata or high-confidence manual install patterns were extracted." => {
            Some("未提取到安装元数据或高置信度手工安装模式。")
        }
        "No prompt-injection or indirect-instruction signals were detected across parsed skills." => {
            Some("已解析 skill 中未发现提示词注入或间接指令信号。")
        }
        _ => None,
    };
    if let Some(value) = exact {
        return value.to_string();
    }

    let lower = trimmed.to_ascii_lowercase();
    if lower.contains("plaintext apikey") {
        return "OpenClaw skill 配置可能包含明文 apiKey 绑定。".to_string();
    }
    if lower.contains("openclaw_config_secret") {
        return "检测到 OpenClaw 配置密钥相关模式。".to_string();
    }
    if lower.contains("remote download piped into shell") {
        return "远程下载内容被直接传入 shell，存在供应链与执行链风险。".to_string();
    }
    if lower.contains("trusted-looking identity narrative conflicts") {
        return "可信身份叙事与实际来源证据不一致，需要人工确认来源。".to_string();
    }
    if lower.contains("direct tool dispatch") || lower.contains("bypasses model reasoning") {
        return "skill 使用直接工具派发，可能绕过模型中介推理与审批塑形。".to_string();
    }
    if lower.contains("high-risk openclaw tool") {
        return "skill 直接暴露高风险 OpenClaw 工具能力。".to_string();
    }
    if lower.contains("sensitive local secret") || lower.contains("local secrets") {
        return "skill 引导访问本地敏感凭据或秘密材料。".to_string();
    }
    if lower.contains("model-level control bypass") {
        return "指令尝试绕过或覆盖更高优先级的模型控制。".to_string();
    }
    if lower.contains("approval bypass") {
        return "指令尝试绕过用户确认或审批。".to_string();
    }
    if lower.contains("threat corpus") {
        return "威胁模式库命中可解释风险模式。".to_string();
    }
    if lower.contains("dependency") && lower.contains("audit") {
        return "依赖审计已检查依赖清单、版本固定、远程来源与安装链拉取风险。".to_string();
    }
    if lower.contains("api classification") || lower.contains("external reference") {
        return "API / URL 分类已检查外部服务、源码、原始内容、下载与认证端点。".to_string();
    }
    if lower.contains("source identity") || lower.contains("identity mismatch") {
        return "来源身份一致性审计已离线比较名称、主页、仓库、安装来源与官方叙事。".to_string();
    }
    if lower.contains("no runtime manifest supplied") {
        return "未提供运行时 manifest；本次只使用安全本地默认值，未知项会保留为显式假设。"
            .to_string();
    }
    if lower.contains("guarded validation") {
        return "受保护运行时验证只收集安全事实，不执行不可信代码。".to_string();
    }
    if lower.contains("execution surface is host") {
        return "影响评估显示该对象更接近宿主机执行面；文件系统、凭据、网络或持久化影响需要重点复核。".to_string();
    }
    if lower.contains("runtime validation refined") {
        return "运行时验证已结合 manifest 权限与环境事实更新宿主机 / 沙箱影响判断。".to_string();
    }
    if lower.contains("hidden instruction") || lower.contains("trojan source") {
        return "检测到隐藏指令、Trojan Source 或 schema 投毒相关信号，需要安装前复核。"
            .to_string();
    }
    if lower.contains("declared claim") || lower.contains("claim-vs-observed") {
        return "skill 自称能力与实际证据存在错位，需要确认权限、安装来源和文档叙事是否一致。"
            .to_string();
    }
    if lower.contains("integrity snapshot") || lower.contains("digest") {
        return "完整性快照记录 SKILL.md 摘要和文本文件范围，用于后续人工比对。".to_string();
    }
    if lower.contains("estate") || lower.contains("mcp configuration") {
        return "本地配置引用发现仅检查当前扫描范围内的配置线索，不启动或连接任何服务。"
            .to_string();
    }
    if lower.contains("agent package") || lower.contains("agent ecosystem") {
        return "Agent package 生态解析会把 skill、规则、MCP 配置和 prompt package 映射到统一视图。"
            .to_string();
    }
    if lower.contains("mcp tool") || lower.contains("schema poisoning") {
        return "MCP tool/schema 静态分析只复核配置和描述文本，不启动 MCP server。".to_string();
    }
    if lower.contains("ai bom") {
        return "AI BOM 汇总 package、工具面、MCP、命令、环境变量、外部服务、依赖和完整性摘要。"
            .to_string();
    }
    if lower.contains("policy did not block") {
        return "当前策略未阻断本次报告。".to_string();
    }
    if lower.contains("source reputation") {
        return "来源信誉摘要基于离线规则、URL 模式与本地种子给出可解释提示。".to_string();
    }
    if lower.contains("mcp") && lower.contains("dangerous command") {
        return "MCP 配置中存在危险 command/env 线索，需要安装前复核。".to_string();
    }
    if lower.contains("it is text-only") && lower.contains("must not execute") {
        return "这是仅用于测试的文本说明；扫描器不应执行其中配置的命令。".to_string();
    }
    if lower.contains("contributes a high severity penalty") {
        return "该发现因高危级别对风险分数产生明显扣分。".to_string();
    }
    if lower.contains("contributes a medium severity penalty") {
        return "该发现因中危级别对风险分数产生扣分。".to_string();
    }
    if lower.contains("finding provenance records") {
        return "来源说明记录了该信号的证据位置和所属风险家族。".to_string();
    }
    if lower.contains("corpus-backed threat finding") {
        return "威胁模式库命中的发现项对风险分数产生高危扣分。".to_string();
    }
    if lower.contains("hidden instruction or trojan source") {
        return "隐藏指令或 Trojan Source 信号对风险分数产生中危扣分。".to_string();
    }
    if lower.contains("capability manifest summarized") {
        return "能力 / 权限视图已汇总声明能力、推断能力、必要能力和不一致信号。".to_string();
    }
    if lower.contains("scanned") && lower.contains("companion document") {
        return "配套文档审计已检查当前扫描范围内的 README、docs 或 examples 类文本。".to_string();
    }
    if lower.contains("tool description") || lower.contains("schema") {
        return "工具描述或输入 schema 中存在需要复核的指令性文本。".to_string();
    }
    trimmed.to_string()
}

pub fn verdict_zh(verdict: Verdict) -> &'static str {
    match verdict {
        Verdict::Allow => "允许",
        Verdict::Warn => "警告",
        Verdict::Block => "阻断",
    }
}

pub fn severity_zh(severity: FindingSeverity) -> &'static str {
    match severity {
        FindingSeverity::Critical => "严重",
        FindingSeverity::High => "高危",
        FindingSeverity::Medium => "中危",
        FindingSeverity::Low => "低危",
        FindingSeverity::Info => "信息",
    }
}

pub fn confidence_zh(confidence: FindingConfidence) -> &'static str {
    match confidence {
        FindingConfidence::High => "高",
        FindingConfidence::Medium => "中",
        FindingConfidence::Low => "低",
        FindingConfidence::InferredCompound => "组合推断",
    }
}

pub fn debug_label_zh<T: Debug>(value: T) -> String {
    debug_token_zh(&format!("{value:?}"))
}

pub fn debug_token_zh(token: &str) -> String {
    match token {
        "Allow" => "允许",
        "Warn" => "警告",
        "Block" => "阻断",
        "Critical" => "严重",
        "High" => "高",
        "Medium" => "中",
        "Low" => "低",
        "Info" => "信息",
        "InferredCompound" => "组合推断",
        "TrustedInfrastructure" => "可信基础设施",
        "KnownPlatform" => "已知平台",
        "ReviewNeeded" => "需要复核",
        "Suspicious" => "可疑",
        "SourceRepository" => "源码仓库",
        "Documentation" => "文档",
        "RawContent" => "原始内容",
        "ApiEndpoint" => "API 端点",
        "AuthEndpoint" => "认证端点",
        "PackageRegistry" => "包注册源",
        "ObjectStorage" => "对象存储",
        "FileDownload" => "文件下载",
        "Shortlink" => "短链接",
        "DynamicDns" => "动态 DNS",
        "DirectIp" => "直接 IP",
        "Unknown" => "未知",
        "SourceCodeHost" => "源码托管",
        "PackageEcosystem" => "包生态",
        "CloudPlatform" => "云平台",
        "AiService" => "AI 服务",
        "GeneralApi" => "通用 API",
        "ContentDelivery" => "内容分发",
        "Validated" => "已验证",
        "PartiallyValidated" => "部分验证",
        "BlockedByEnvironment" => "被环境阻断",
        "StillAssumed" => "仍为假设",
        "ScopeIncomplete" => "扫描范围不完整",
        "NotChecked" => "未检查",
        "AllowedByGuard" => "运行时允许",
        "DeniedByGuard" => "运行时拒绝",
        "Active" => "生效",
        "Expired" => "已过期",
        "Invalid" => "无效",
        "Applied" => "已应用",
        "Warning" => "警告",
        "Error" => "错误",
        "Instruction" => "指令",
        "UntrustedContent" => "不可信内容",
        "PromptInjection" => "提示词注入",
        "DirectToolDispatch" => "直接工具派发",
        "ToolUse" => "工具使用",
        "SecretAccess" => "敏感信息访问",
        "Execution" => "执行能力",
        "ConfigMutation" => "配置修改",
        "NetworkEgress" => "网络外联",
        "InstallExecution" => "安装执行",
        "PrecedenceHijack" => "优先级劫持",
        "Persistence" => "持久化",
        "HostPrivilege" => "宿主权限",
        "SandboxResidualRisk" => "沙箱残余风险",
        "OpenClawSkill" => "OpenClaw skill",
        "ClaudeSkill" => "Claude skill",
        "CursorRule" => "Cursor 规则",
        "WindsurfRule" => "Windsurf 规则",
        "CodexSkill" => "Codex skill",
        "ClineRule" => "Cline 规则",
        "McpConfig" => "MCP 配置",
        "GenericPromptPackage" => "通用 prompt package",
        "UnknownAgentAsset" => "未知 Agent 资产",
        "LocalPath" => "本地路径",
        "GithubRepo" => "GitHub 仓库",
        "GithubTree" => "GitHub tree",
        "GithubBlob" => "GitHub blob",
        "RawSkill" => "原始 SKILL.md",
        "ZipArchive" => "ZIP 归档",
        "HttpsSkill" => "HTTPS skill 链接",
        "ShortlinkHost" => "短链接主机",
        "RawDownload" => "原始下载",
        "PureIp" => "直接 IP",
        "DynamicDnsSuffix" => "动态 DNS 后缀",
        "SuspiciousTld" => "可疑 TLD",
        "NonHttps" => "非 HTTPS",
        "DirectFileDownload" => "直接文件下载",
        "KnownSuspiciousSeed" => "可疑种子命中",
        _ => token,
    }
    .to_string()
}

pub fn enrich_finding_zh(finding: &mut Finding) {
    if finding.title_zh.is_none() {
        finding.title_zh = Some(zh_text(&finding.title));
    }
    if finding.explanation_zh.is_none() {
        finding.explanation_zh = Some(zh_text(&finding.explanation));
    }
    if finding.recommendation_zh.is_none() && !finding.remediation.is_empty() {
        finding.recommendation_zh = Some(zh_text(&finding.remediation));
    }
}

pub fn enrich_report_zh(report: &mut ScanReport) {
    for finding in &mut report.findings {
        enrich_finding_zh(finding);
    }
    report.summary_zh = Some(format!(
        "结论：{}；风险分数：{}；发现项：{}；攻击路径：{}。",
        verdict_zh(report.verdict),
        report.score,
        report.findings.len(),
        report.attack_paths.len()
    ));
}
