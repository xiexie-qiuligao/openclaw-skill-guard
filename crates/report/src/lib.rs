use agent_skill_guard_core::{
    localization::{confidence_zh, debug_label_zh, severity_zh, verdict_zh, zh_text},
    ScanReport,
};
use serde_json::{json, Value};

pub fn render_json(report: &ScanReport) -> Result<String, serde_json::Error> {
    serde_json::to_string_pretty(report)
}

pub fn render_sarif(report: &ScanReport) -> Result<String, serde_json::Error> {
    let mut rule_index = std::collections::BTreeMap::<String, Value>::new();
    let mut results = Vec::<Value>::new();

    for finding in &report.findings {
        let rule_id = finding.issue_code.as_deref().unwrap_or(&finding.id);
        rule_index.entry(rule_id.to_string()).or_insert_with(|| {
            json!({
                "id": rule_id,
                "name": finding.category,
                "shortDescription": {
                    "text": finding.title_zh.as_deref().unwrap_or(&finding.title),
                },
                "properties": {
                    "category": finding.category,
                    "finding_id": finding.id,
                }
            })
        });

        let locations = finding
            .location
            .as_ref()
            .map(|location| {
                vec![json!({
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": location.path,
                        },
                        "region": {
                            "startLine": location.line.unwrap_or(1),
                            "startColumn": location.column.unwrap_or(1),
                        }
                    }
                })]
            })
            .unwrap_or_default();

        results.push(json!({
            "ruleId": rule_id,
            "level": sarif_level(finding.severity),
            "message": {
                "text": finding
                    .explanation_zh
                    .clone()
                    .unwrap_or_else(|| zh_text(&finding.explanation)),
            },
            "locations": locations,
            "properties": {
                "severity": format!("{:?}", finding.severity).to_ascii_lowercase(),
                "confidence": format!("{:?}", finding.confidence).to_ascii_lowercase(),
                "severity_zh": severity_zh(finding.severity),
                "confidence_zh": confidence_zh(finding.confidence),
                "issue_code": finding.issue_code,
                "finding_id": finding.id,
                "english_message": finding.explanation,
                "hard_trigger": finding.hard_trigger,
                "why_openclaw_specific": finding.why_openclaw_specific,
                "suppression_status": finding.suppression_status,
            }
        }));
    }

    serde_json::to_string_pretty(&json!({
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "agent-skill-guard",
                        "informationUri": "https://example.invalid/agent-skill-guard",
                        "rules": rule_index.into_values().collect::<Vec<_>>(),
                    }
                },
                "results": results,
            }
        ]
    }))
}

pub fn render_markdown(report: &ScanReport) -> String {
    let mut out = String::new();
    out.push_str("# Agent Skill Guard 安全报告\n\n");
    out.push_str("## 总览\n\n");
    out.push_str(&format!(
        "- 扫描目标：`{}`\n- 最终结论：`{}`\n- 风险分数：`{}`\n- 是否阻断：`{}`\n- 发现项：`{}`\n- 攻击路径：`{}`\n- 外部引用：`{}`\n\n",
        safe_report_path(&report.target.path),
        verdict_zh(report.verdict),
        report.score,
        if report.blocked { "是" } else { "否" },
        report.findings.len(),
        report.attack_paths.len(),
        report.external_references.len(),
    ));
    out.push_str("> 提醒：未发现高风险项并不等于绝对安全；请结合来源、权限、安装链和运行环境做最终复核。\n\n");
    if let Some(origin) = &report.input_origin {
        out.push_str(&format!(
            "- 输入来源：`{}` / `{}`\n- 解析目标：`{}`\n\n",
            debug_label_zh(&origin.resolved_kind),
            origin.original_input,
            safe_report_path(&origin.resolved_path)
        ));
    }

    out.push_str("## v2 风险摘要\n\n");
    out.push_str(&format!(
        "- 威胁模式库：{}\n- 敏感数据：{}\n- 依赖审计：{}\n- API / URL 分类：{}\n- 来源信誉：{}\n\n",
        zh_text(report
            .context_analysis
            .threat_corpus_summary
            .as_deref()
            .unwrap_or("n/a")),
        zh_text(report
            .context_analysis
            .sensitive_data_summary
            .as_deref()
            .unwrap_or("n/a")),
        zh_text(&report.dependency_audit_summary.summary),
        zh_text(&report.api_classification_summary.summary),
        zh_text(&report.source_reputation_summary.summary),
    ));

    out.push_str("## OpenClaw 专项摘要\n\n");
    out.push_str(&format!(
        "- 配置 / 控制面：{}\n- 能力 / 权限视图：{}\n- 配套文档：{}\n- 来源身份：{}\n- 隐藏指令：{}\n- 声明与实际：{}\n- 完整性快照：{}\n- 本地配置引用：{}\n- 组合风险：{}\n\n",
        zh_text(&report.openclaw_config_audit_summary.summary),
        zh_text(&report.capability_manifest.summary),
        zh_text(&report.companion_doc_audit_summary.summary),
        zh_text(&report.source_identity_summary.summary),
        report.hidden_instruction_summary.summary_zh,
        report.claims_review_summary.summary_zh,
        report.integrity_snapshot.summary_zh,
        report.estate_inventory_summary.summary_zh,
        report.toxic_flow_summary.summary_zh,
    ));
    out.push_str("## Agent 生态与 AI BOM\n\n");
    out.push_str(&format!(
        "- Agent package：{}\n- MCP / Tool Schema：{}\n- AI BOM：{}\n\n",
        report.agent_package_index.summary_zh,
        report.mcp_tool_schema_summary.summary_zh,
        report.ai_bom.summary_zh,
    ));
    push_string_list_markdown(&mut out, "AI BOM package 清单", &report.ai_bom.packages);
    push_string_list_markdown(&mut out, "AI BOM 工具面", &report.ai_bom.tool_surfaces);
    push_string_list_markdown(&mut out, "AI BOM MCP server", &report.ai_bom.mcp_servers);
    push_string_list_markdown(&mut out, "AI BOM 命令面", &report.ai_bom.commands);
    push_string_list_markdown(
        &mut out,
        "AI BOM 环境变量 / 配置",
        &report.ai_bom.env_and_config,
    );
    push_string_list_markdown(
        &mut out,
        "AI BOM 外部服务",
        &report.ai_bom.external_services,
    );
    push_string_list_markdown(&mut out, "AI BOM 复核问题", &report.ai_bom.review_questions);
    out.push_str("## 策略与 CI\n\n");
    out.push_str(&format!(
        "- 策略结果：{}\n- CI 模式：`{}`\n- 是否阻断：`{}`\n\n",
        report.policy_evaluation.reason_zh,
        report.policy_evaluation.ci_mode,
        if report.policy_evaluation.blocked {
            "是"
        } else {
            "否"
        },
    ));
    push_string_list_markdown(
        &mut out,
        "策略忽略的规则",
        &report.policy_evaluation.ignored_rules,
    );
    push_string_list_markdown(
        &mut out,
        "策略忽略的发现项",
        &report.policy_evaluation.ignored_findings,
    );
    push_string_list_markdown(
        &mut out,
        "策略 severity override",
        &report.policy_evaluation.severity_overrides_applied,
    );
    push_string_list_markdown(
        &mut out,
        "允许域名匹配",
        &report.policy_evaluation.allowed_domain_matches,
    );
    push_string_list_markdown(
        &mut out,
        "忽略路径匹配",
        &report.policy_evaluation.ignored_path_matches,
    );
    push_string_list_markdown(
        &mut out,
        "配置 / 控制面风险绑定",
        &report.openclaw_config_audit_summary.risky_bindings,
    );
    if !report.capability_manifest.entries.is_empty() {
        out.push_str("### 能力 / 权限条目\n\n");
        for entry in &report.capability_manifest.entries {
            out.push_str(&format!(
                "- {}：{}（来源：{}）\n",
                display_capability_label(&entry.capability),
                zh_text(&entry.rationale),
                display_source_label(&entry.source)
            ));
        }
        out.push('\n');
    }
    push_string_list_markdown(
        &mut out,
        "能力风险组合",
        &report.capability_manifest.risky_combinations,
    );
    push_string_list_markdown(
        &mut out,
        "配套文档投毒信号",
        &report.companion_doc_audit_summary.poisoning_signals,
    );
    if !report.source_identity_summary.signals.is_empty() {
        out.push_str("### 来源身份信号\n\n");
        for signal in &report.source_identity_summary.signals {
            out.push_str(&format!(
                "- `{}` | `{}`: {}\n",
                signal.signal_id, signal.signal_kind, signal.summary
            ));
        }
        out.push('\n');
    }
    if !report.hidden_instruction_summary.signals.is_empty() {
        out.push_str("### 隐藏指令 / Trojan Source 信号\n\n");
        for signal in &report.hidden_instruction_summary.signals {
            out.push_str(&format!(
                "- `{}` | `{}` | `{}`:{}：{}\n",
                signal.signal_id,
                signal.signal_kind,
                safe_report_path(&signal.path),
                signal.line.unwrap_or(1),
                signal.rationale_zh
            ));
        }
        out.push('\n');
    }
    if !report.claims_review_summary.mismatches.is_empty() {
        out.push_str("### 声明 vs 实际证据\n\n");
        for mismatch in &report.claims_review_summary.mismatches {
            out.push_str(&format!(
                "- 声明：{}；实际证据：{}；复核问题：{}\n",
                mismatch.claim, mismatch.observed_signal, mismatch.review_question
            ));
        }
        out.push('\n');
    }
    if !report.integrity_snapshot.skill_file_digests.is_empty() {
        out.push_str("### 完整性快照\n\n");
        for digest in &report.integrity_snapshot.skill_file_digests {
            out.push_str(&format!(
                "- `{}`：SHA-256 `{}`，{} bytes\n",
                safe_report_path(&digest.path),
                digest.sha256,
                digest.bytes
            ));
        }
        out.push('\n');
    }
    if !report.estate_inventory_summary.references.is_empty() {
        out.push_str("### 本地配置引用\n\n");
        for reference in &report.estate_inventory_summary.references {
            out.push_str(&format!(
                "- `{}` | `{}` | `{}`：{}\n",
                reference.reference_id,
                reference.reference_kind,
                safe_report_path(&reference.path),
                reference.summary_zh
            ));
        }
        out.push('\n');
    }

    out.push_str("## 发现项\n\n");
    if report.findings.is_empty() {
        out.push_str("未发现需要展示的风险项。\n\n");
    } else {
        for finding in &report.findings {
            out.push_str(&format!(
                "### {}\n\n- 问题编号：`{}`\n- 严重级别：`{}`\n- 可信度：`{}`\n",
                finding.title_zh.as_deref().unwrap_or(&finding.title),
                finding.issue_code.as_deref().unwrap_or("n/a"),
                severity_zh(finding.severity),
                confidence_zh(finding.confidence),
            ));
            if let Some(location) = &finding.location {
                out.push_str(&format!(
                    "- 位置：`{}`:{}\n",
                    safe_report_path(&location.path),
                    location.line.unwrap_or(1)
                ));
            }
            out.push_str(&format!(
                "\n{}\n\n",
                finding
                    .explanation_zh
                    .clone()
                    .unwrap_or_else(|| zh_text(&finding.explanation))
            ));
            if !finding.analyst_notes.is_empty() {
                out.push_str("证据详情：\n");
                for note in &finding.analyst_notes {
                    out.push_str(&format!("- {}\n", zh_text(note)));
                }
                out.push('\n');
            }
        }
    }

    out.push_str("## 上下文\n\n");
    push_optional_markdown(
        &mut out,
        "解析",
        Some(&report.context_analysis.parsing_summary),
    );
    push_optional_markdown(
        &mut out,
        "元数据",
        report.context_analysis.metadata_summary.as_deref(),
    );
    push_optional_markdown(
        &mut out,
        "安装链",
        report.context_analysis.install_chain_summary.as_deref(),
    );
    push_optional_markdown(
        &mut out,
        "提示词 / 间接指令",
        report.context_analysis.prompt_injection_summary.as_deref(),
    );
    push_optional_markdown(
        &mut out,
        "威胁模式库",
        report.context_analysis.threat_corpus_summary.as_deref(),
    );
    push_optional_markdown(
        &mut out,
        "敏感数据",
        report.context_analysis.sensitive_data_summary.as_deref(),
    );
    push_optional_markdown(
        &mut out,
        "依赖审计",
        report.context_analysis.dependency_audit_summary.as_deref(),
    );
    push_optional_markdown(
        &mut out,
        "API / URL 分类",
        report
            .context_analysis
            .api_classification_summary
            .as_deref(),
    );
    push_optional_markdown(
        &mut out,
        "来源信誉",
        report.context_analysis.source_reputation_summary.as_deref(),
    );
    push_optional_markdown(
        &mut out,
        "OpenClaw 配置 / 控制面",
        report.context_analysis.openclaw_config_summary.as_deref(),
    );
    push_optional_markdown(
        &mut out,
        "能力 / 权限视图",
        report
            .context_analysis
            .capability_manifest_summary
            .as_deref(),
    );
    push_optional_markdown(
        &mut out,
        "配套文档",
        report
            .context_analysis
            .companion_doc_audit_summary
            .as_deref(),
    );
    push_optional_markdown(
        &mut out,
        "来源身份",
        report.context_analysis.source_identity_summary.as_deref(),
    );

    out.push_str("## 攻击路径\n\n");
    if report.attack_paths.is_empty() {
        out.push_str("未形成达到阈值的攻击路径。\n\n");
    } else {
        for path in &report.attack_paths {
            out.push_str(&format!(
                "### {} (`{}`)\n\n- 严重级别：`{}`\n- 置信度：`{}`\n- 类型：`{}`\n\n{}\n\n",
                path.title,
                path.path_id,
                severity_zh(path.severity),
                confidence_zh(path.confidence),
                path.path_type,
                path.explanation
            ));
        }
    }

    out.push_str("## 运行时验证与影响评估\n\n");
    out.push_str(&format!(
        "- 运行时 manifest：{}\n- 受保护验证：{}\n- 影响评估：{}\n- 宿主机 / 沙箱：{}\n\n",
        zh_text(&report.runtime_manifest_summary),
        zh_text(&report.guarded_validation.summary),
        zh_text(&report.consequence_summary.summary),
        zh_text(&report.host_vs_sandbox_split.summary),
    ));

    out.push_str("## 外部引用\n\n");
    if report.external_references.is_empty() {
        out.push_str("未发现外部引用。\n\n");
    } else {
        for reference in &report.external_references {
            out.push_str(&format!(
                "- `{}` | category `{}` | reputation `{}` | host `{}`\n",
                reference.url,
                debug_label_zh(reference.category),
                debug_label_zh(reference.reputation),
                reference.host
            ));
        }
        out.push('\n');
    }

    out.push_str("## 评分与来源说明\n\n");
    for item in &report.scoring_summary.score_rationale {
        out.push_str(&format!(
            "- {}（影响：{}）：{}\n",
            display_source_label(&item.source),
            item.delta,
            zh_text(&item.explanation),
        ));
    }
    if !report.confidence_factors.is_empty() {
        out.push_str("\n置信度因素：\n");
        for factor in &report.confidence_factors {
            out.push_str(&format!(
                "- {}（影响：{}）：{}\n",
                display_source_label(&factor.subject_id),
                factor.delta,
                zh_text(&factor.rationale),
            ));
        }
    }
    if !report.provenance_notes.is_empty() {
        out.push_str("\n来源说明：\n");
        for note in &report.provenance_notes {
            out.push_str(&format!(
                "- {}：{}\n",
                display_source_label(&note.subject_id),
                zh_text(&note.note)
            ));
        }
    }

    out
}

fn display_source_label(raw: &str) -> String {
    let lower = raw.to_ascii_lowercase();
    if lower.contains("confidence") || raw == "可信度调整" {
        return "可信度调整".to_string();
    }
    if lower.contains("external") || lower.contains("reference") || lower.contains("url") {
        return "外部引用证据".to_string();
    }
    if lower.contains("source_identity") || lower.contains("claims_review") {
        return "身份与声明一致性证据".to_string();
    }
    if lower.contains("dependency") || lower.contains("install") {
        return "安装与依赖证据".to_string();
    }
    if lower.contains("openclaw_config") || lower.contains("config") {
        return "配置证据".to_string();
    }
    if lower.contains("toxic_flow") || lower.contains("flow") {
        return "组合风险证据".to_string();
    }
    if lower.contains("mcp") {
        return "MCP / 工具证据".to_string();
    }
    if lower.contains("prompt") || lower.contains("instruction") {
        return "指令文本证据".to_string();
    }
    if raw.chars().count() > 48 {
        return "详细证据".to_string();
    }
    zh_text(raw)
}

fn display_capability_label(raw: &str) -> String {
    let lower = raw.to_ascii_lowercase();
    if lower.contains("network") || lower.contains("external") || lower.contains("url") {
        return "外部网络 / 链接访问".to_string();
    }
    if lower.contains("secret") || lower.contains("credential") || lower.contains("apikey") {
        return "密钥 / 凭据访问".to_string();
    }
    if lower.contains("exec") || lower.contains("shell") || lower.contains("process") {
        return "命令执行能力".to_string();
    }
    if lower.contains("file") || lower.contains("write") || lower.contains("read") {
        return "文件读写能力".to_string();
    }
    if lower.contains("browser") || lower.contains("web") {
        return "浏览器 / 网页访问".to_string();
    }
    zh_text(raw)
}

pub fn render_html(report: &ScanReport) -> String {
    let markdown = render_markdown(report);
    format!(
        "<!DOCTYPE html><html lang=\"zh-CN\"><head><meta charset=\"utf-8\"><title>Agent Skill Guard 安全报告</title><style>body{{font-family:Segoe UI,Microsoft YaHei,Arial,sans-serif;max-width:1100px;margin:0 auto;padding:24px;line-height:1.6;background:#f4f7fb;color:#1f2933}}section{{background:#fff;border:1px solid #d8e2eb;border-radius:12px;padding:18px;margin:0 0 16px;box-shadow:0 4px 18px rgba(15,23,42,.05)}}code{{background:#eef4f8;padding:2px 4px;border-radius:4px}}pre{{white-space:pre-wrap;word-break:break-word}}</style></head><body><section><pre>{}</pre></section></body></html>",
        escape_html(&markdown)
    )
}

fn sarif_level(severity: agent_skill_guard_core::FindingSeverity) -> &'static str {
    match severity {
        agent_skill_guard_core::FindingSeverity::Critical
        | agent_skill_guard_core::FindingSeverity::High => "error",
        agent_skill_guard_core::FindingSeverity::Medium => "warning",
        agent_skill_guard_core::FindingSeverity::Low
        | agent_skill_guard_core::FindingSeverity::Info => "note",
    }
}

fn push_optional_markdown(out: &mut String, label: &str, value: Option<&str>) {
    if let Some(value) = value {
        if !value.is_empty() {
            out.push_str(&format!("### {}\n\n{}\n\n", label, zh_text(value)));
        }
    }
}

fn push_string_list_markdown(out: &mut String, label: &str, values: &[String]) {
    if values.is_empty() {
        return;
    }
    out.push_str(&format!("### {}\n\n", label));
    for value in values {
        out.push_str(&format!("- {}\n", zh_text(value)));
    }
    out.push('\n');
}

fn safe_report_path(path: &str) -> String {
    let normalized = path.replace('\\', "/");
    if normalized.starts_with("<remote-") {
        return normalized;
    }
    let parts = normalized
        .split('/')
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>();
    match parts.as_slice() {
        [] => "未命名目标".to_string(),
        [one] => (*one).to_string(),
        _ => parts[parts.len().saturating_sub(2)..].join("/"),
    }
}

fn escape_html(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

#[cfg(test)]
mod tests {
    use agent_skill_guard_core::{
        ApiClassificationSummary, AuditSummary, ConsequenceAssessment, ConstraintEffect,
        ContextAnalysis, DependencyAuditSummary, EnvironmentAmplifier, EnvironmentBlocker,
        ExecutionSurface, ExternalReference, HostSandboxSplit, Recommendations,
        ReferenceClassificationProvenance, RootResolutionSummary, RuntimeAssumptionStatus,
        RuntimeFact, RuntimeRefinementNote, RuntimeScoreAdjustment, RuntimeSourceKind, ScanReport,
        ScanTarget, ScoringSummary, SourceReputationSummary, SuppressionLifecycle, TargetKind,
        ValidationPlan, ValidationResult, ValidationTarget, Verdict,
    };
    use serde_json::Value;

    use super::{render_html, render_json, render_markdown, render_sarif};

    #[test]
    fn json_renderer_emits_expected_top_level_fields() {
        let report = ScanReport {
            input_origin: None,
            target: ScanTarget {
                path: "SKILL.md".to_string(),
                canonical_path: "SKILL.md".to_string(),
                target_kind: TargetKind::File,
            },
            scan_mode: "file".to_string(),
            files_scanned: 1,
            files_skipped: Vec::new(),
            parse_errors: Vec::new(),
            score: 100,
            verdict: Verdict::Allow,
            blocked: false,
            top_risks: Vec::new(),
            findings: Vec::new(),
            context_analysis: ContextAnalysis {
                phase: "phase5_attack_paths".to_string(),
                parsing_summary: "parsed".to_string(),
                metadata_summary: None,
                install_chain_summary: None,
                invocation_summary: None,
                tool_reachability_summary: None,
                reachable_tools: Vec::new(),
                secret_reachability_summary: None,
                reachable_secret_scopes: Vec::new(),
                precedence_summary: None,
                naming_collisions: Vec::new(),
                host_vs_sandbox_assessment: None,
                prompt_injection_summary: None,
                threat_corpus_summary: None,
                sensitive_data_summary: None,
                dependency_audit_summary: None,
                api_classification_summary: None,
                source_reputation_summary: None,
                openclaw_config_summary: None,
                capability_manifest_summary: None,
                companion_doc_audit_summary: None,
                source_identity_summary: None,
                hidden_instruction_summary: None,
                claims_review_summary: None,
                integrity_snapshot_summary: None,
                estate_inventory_summary: None,
                agent_package_summary: None,
                mcp_tool_schema_summary: None,
                ai_bom_summary: None,
                notes: Vec::new(),
            },
            agent_package_index: Default::default(),
            mcp_tool_schema_summary: Default::default(),
            ai_bom: Default::default(),
            attack_paths: Vec::new(),
            path_explanations: Vec::new(),
            prompt_injection_summary: String::new(),
            consequence_summary: ConsequenceAssessment {
                execution_surface: ExecutionSurface::Uncertain,
                file_system_consequences: Vec::new(),
                credential_consequences: Vec::new(),
                network_consequences: Vec::new(),
                persistence_consequences: Vec::new(),
                environment_assumptions: Vec::new(),
                evidence_nodes: Vec::new(),
                inferred_notes: Vec::new(),
                impact_deltas: Vec::new(),
                summary: String::new(),
            },
            host_vs_sandbox_split: HostSandboxSplit {
                host_effects: Vec::new(),
                sandbox_effects: Vec::new(),
                blocked_in_sandbox: Vec::new(),
                residual_sandbox_risks: Vec::new(),
                summary: String::new(),
            },
            runtime_manifest_summary: "No runtime manifest supplied.".to_string(),
            guarded_validation: agent_skill_guard_core::GuardedValidationResult {
                summary: "No guarded validation facts.".to_string(),
                capability_checks: Vec::new(),
                constraint_checks: Vec::new(),
                sandbox_constraint_effects: Vec::new(),
            },
            runtime_facts: vec![RuntimeFact {
                key: "execution_environment".to_string(),
                value: "Unknown".to_string(),
                source_kind: RuntimeSourceKind::Unknown,
                confirmed: false,
            }],
            runtime_assumption_status: vec![RuntimeAssumptionStatus {
                assumption: "execution_environment".to_string(),
                state: agent_skill_guard_core::RuntimeAssumptionState::Unknown,
                source_kind: RuntimeSourceKind::Unknown,
                rationale: "No manifest".to_string(),
            }],
            validation_plan: ValidationPlan {
                summary: String::new(),
                hooks: Vec::new(),
            },
            validation_hooks: Vec::new(),
            validation_results: vec![ValidationResult {
                check_id: "runtime.environment".to_string(),
                target: ValidationTarget::RuntimeEnvironment,
                success: false,
                validated_constraints: Vec::new(),
                missing_constraints: Vec::new(),
                capability_checks: Vec::new(),
                constraint_checks: Vec::new(),
                sandbox_constraint_effects: Vec::new(),
                note: "No manifest".to_string(),
            }],
            path_validation_status: Vec::new(),
            runtime_refinement_notes: vec![RuntimeRefinementNote {
                subject_id: "path.example".to_string(),
                note: "Still assumed".to_string(),
            }],
            constraint_effects: vec![ConstraintEffect {
                subject_id: "path.example".to_string(),
                effect: "still_assumed".to_string(),
                rationale: "No runtime facts".to_string(),
            }],
            environment_blockers: vec![EnvironmentBlocker {
                path_id: "path.example".to_string(),
                blocker: "network_denied".to_string(),
                rationale: "Example".to_string(),
            }],
            environment_amplifiers: vec![EnvironmentAmplifier {
                path_id: "path.example".to_string(),
                amplifier: "host_home_access".to_string(),
                rationale: "Example".to_string(),
            }],
            validation_score_adjustments: vec![RuntimeScoreAdjustment {
                source: "path.example".to_string(),
                delta: 1,
                rationale: "Example".to_string(),
            }],
            corpus_assets_used: Vec::new(),
            dependency_audit_summary: DependencyAuditSummary {
                summary: "No dependency findings.".to_string(),
                manifests_discovered: Vec::new(),
                lockfile_gaps: Vec::new(),
                findings_count: 0,
                notes: Vec::new(),
            },
            api_classification_summary: ApiClassificationSummary {
                summary: "No external references.".to_string(),
                total_references: 0,
                category_counts: Default::default(),
                service_kind_counts: Default::default(),
                review_needed_count: 0,
            },
            source_reputation_summary: SourceReputationSummary {
                summary: "No reputation hints.".to_string(),
                suspicious_references: 0,
                risk_signal_counts: Default::default(),
                notes: Vec::new(),
            },
            external_references: vec![ExternalReference {
                reference_id: "ref-001".to_string(),
                url: "https://github.com/example/project".to_string(),
                host: "github.com".to_string(),
                category: agent_skill_guard_core::ExternalReferenceCategory::SourceRepository,
                service_kind: agent_skill_guard_core::ExternalServiceKind::SourceCodeHost,
                reputation: agent_skill_guard_core::ExternalReferenceReputation::KnownPlatform,
                risk_signals: Vec::new(),
                locations: Vec::new(),
                evidence_excerpt: "https://github.com/example/project".to_string(),
                rationale: "fixture".to_string(),
                provenance: ReferenceClassificationProvenance {
                    taxonomy_entry_id: Some("v2.api.github_repo".to_string()),
                    matched_seed_ids: Vec::new(),
                    asset_sources: vec!["api-taxonomy-v2.yaml".to_string()],
                },
            }],
            openclaw_config_audit_summary: Default::default(),
            capability_manifest: Default::default(),
            companion_doc_audit_summary: Default::default(),
            source_identity_summary: Default::default(),
            toxic_flow_summary: Default::default(),
            toxic_flows: Vec::new(),
            hidden_instruction_summary: Default::default(),
            claims_review_summary: Default::default(),
            integrity_snapshot: Default::default(),
            estate_inventory_summary: Default::default(),
            policy_evaluation: Default::default(),
            provenance_notes: Vec::new(),
            confidence_factors: Vec::new(),
            false_positive_mitigations: Vec::new(),
            scoring_summary: ScoringSummary {
                base_score: 100,
                compound_uplift: 0,
                path_uplift: 0,
                confidence_adjustment: 0,
                final_score: 100,
                score_rationale: Vec::new(),
            },
            summary_zh: None,
            openclaw_specific_risk_summary: String::new(),
            scope_resolution_summary: RootResolutionSummary {
                known_roots: Vec::new(),
                missing_roots: Vec::new(),
                scope_notes: Vec::new(),
                summary: String::new(),
            },
            audit_summary: AuditSummary {
                summary: String::new(),
                records: Vec::new(),
                high_risk_suppressions: 0,
                expired_suppressions: Vec::new(),
                validation_aware_notes: Vec::new(),
            },
            suppression_matches: vec![agent_skill_guard_core::SuppressionMatch {
                scope: "finding".to_string(),
                target_id: "example".to_string(),
                reason: "fixture".to_string(),
                note: None,
                high_risk: false,
                lifecycle: SuppressionLifecycle::Active,
            }],
            analysis_limitations: Vec::new(),
            confidence_notes: Vec::new(),
            recommendations: Recommendations {
                immediate: Vec::new(),
                short_term: Vec::new(),
                hardening: Vec::new(),
                dynamic_validation: Vec::new(),
            },
            suppressions: Vec::new(),
            scan_integrity_notes: Vec::new(),
        };

        let rendered = render_json(&report).unwrap();

        assert!(rendered.contains("\"scan_mode\""));
        assert!(rendered.contains("\"context_analysis\""));
        assert!(rendered.contains("\"recommendations\""));
        assert!(rendered.contains("\"parsing_summary\""));
        assert!(rendered.contains("\"attack_paths\""));
        assert!(rendered.contains("\"scoring_summary\""));
        assert!(rendered.contains("\"validation_plan\""));
        assert!(rendered.contains("\"consequence_summary\""));
        assert!(rendered.contains("\"runtime_manifest_summary\""));
        assert!(rendered.contains("\"validation_results\""));
        assert!(rendered.contains("\"path_validation_status\""));
        assert!(rendered.contains("\"validation_score_adjustments\""));
        assert!(rendered.contains("\"dependency_audit_summary\""));
        assert!(rendered.contains("\"external_references\""));
        assert!(rendered.contains("\"source_reputation_summary\""));
    }

    #[test]
    fn sarif_renderer_maps_findings_into_results() {
        let mut report = serde_json::from_str::<ScanReport>(
            &render_json(&ScanReport {
                input_origin: None,
                target: ScanTarget {
                    path: "SKILL.md".to_string(),
                    canonical_path: "SKILL.md".to_string(),
                    target_kind: TargetKind::File,
                },
                scan_mode: "file".to_string(),
                files_scanned: 1,
                files_skipped: Vec::new(),
                parse_errors: Vec::new(),
                score: 90,
                verdict: Verdict::Warn,
                blocked: false,
                top_risks: Vec::new(),
                findings: Vec::new(),
                context_analysis: ContextAnalysis {
                    phase: "phase7_runtime_adapter".to_string(),
                    parsing_summary: "parsed".to_string(),
                    metadata_summary: None,
                    install_chain_summary: None,
                    invocation_summary: None,
                    tool_reachability_summary: None,
                    reachable_tools: Vec::new(),
                    secret_reachability_summary: None,
                    reachable_secret_scopes: Vec::new(),
                    precedence_summary: None,
                    naming_collisions: Vec::new(),
                    host_vs_sandbox_assessment: None,
                    prompt_injection_summary: None,
                    threat_corpus_summary: None,
                    sensitive_data_summary: None,
                    dependency_audit_summary: None,
                    api_classification_summary: None,
                    source_reputation_summary: None,
                    openclaw_config_summary: None,
                    capability_manifest_summary: None,
                    companion_doc_audit_summary: None,
                    source_identity_summary: None,
                    hidden_instruction_summary: None,
                    claims_review_summary: None,
                    integrity_snapshot_summary: None,
                    estate_inventory_summary: None,
                    agent_package_summary: None,
                    mcp_tool_schema_summary: None,
                    ai_bom_summary: None,
                    notes: Vec::new(),
                },
                agent_package_index: Default::default(),
                mcp_tool_schema_summary: Default::default(),
                ai_bom: Default::default(),
                attack_paths: Vec::new(),
                path_explanations: Vec::new(),
                prompt_injection_summary: String::new(),
                consequence_summary: ConsequenceAssessment {
                    execution_surface: ExecutionSurface::Uncertain,
                    file_system_consequences: Vec::new(),
                    credential_consequences: Vec::new(),
                    network_consequences: Vec::new(),
                    persistence_consequences: Vec::new(),
                    environment_assumptions: Vec::new(),
                    evidence_nodes: Vec::new(),
                    inferred_notes: Vec::new(),
                    impact_deltas: Vec::new(),
                    summary: String::new(),
                },
                host_vs_sandbox_split: HostSandboxSplit {
                    host_effects: Vec::new(),
                    sandbox_effects: Vec::new(),
                    blocked_in_sandbox: Vec::new(),
                    residual_sandbox_risks: Vec::new(),
                    summary: String::new(),
                },
                runtime_manifest_summary: "No runtime manifest supplied.".to_string(),
                guarded_validation: agent_skill_guard_core::GuardedValidationResult {
                    summary: String::new(),
                    capability_checks: Vec::new(),
                    constraint_checks: Vec::new(),
                    sandbox_constraint_effects: Vec::new(),
                },
                runtime_facts: Vec::new(),
                runtime_assumption_status: Vec::new(),
                validation_plan: ValidationPlan {
                    summary: String::new(),
                    hooks: Vec::new(),
                },
                validation_hooks: Vec::new(),
                validation_results: Vec::new(),
                path_validation_status: Vec::new(),
                runtime_refinement_notes: Vec::new(),
                constraint_effects: Vec::new(),
                environment_blockers: Vec::new(),
                environment_amplifiers: Vec::new(),
                validation_score_adjustments: Vec::new(),
                corpus_assets_used: Vec::new(),
                dependency_audit_summary: DependencyAuditSummary {
                    summary: String::new(),
                    manifests_discovered: Vec::new(),
                    lockfile_gaps: Vec::new(),
                    findings_count: 0,
                    notes: Vec::new(),
                },
                api_classification_summary: ApiClassificationSummary {
                    summary: String::new(),
                    total_references: 0,
                    category_counts: Default::default(),
                    service_kind_counts: Default::default(),
                    review_needed_count: 0,
                },
                source_reputation_summary: SourceReputationSummary {
                    summary: String::new(),
                    suspicious_references: 0,
                    risk_signal_counts: Default::default(),
                    notes: Vec::new(),
                },
                external_references: Vec::new(),
                openclaw_config_audit_summary: Default::default(),
                capability_manifest: Default::default(),
                companion_doc_audit_summary: Default::default(),
                source_identity_summary: Default::default(),
                toxic_flow_summary: Default::default(),
                toxic_flows: Vec::new(),
                hidden_instruction_summary: Default::default(),
                claims_review_summary: Default::default(),
                integrity_snapshot: Default::default(),
                estate_inventory_summary: Default::default(),
                policy_evaluation: Default::default(),
                provenance_notes: Vec::new(),
                confidence_factors: Vec::new(),
                false_positive_mitigations: Vec::new(),
                scoring_summary: ScoringSummary {
                    base_score: 90,
                    compound_uplift: 0,
                    path_uplift: 0,
                    confidence_adjustment: 0,
                    final_score: 90,
                    score_rationale: Vec::new(),
                },
                summary_zh: None,
                openclaw_specific_risk_summary: String::new(),
                scope_resolution_summary: RootResolutionSummary {
                    known_roots: Vec::new(),
                    missing_roots: Vec::new(),
                    scope_notes: Vec::new(),
                    summary: String::new(),
                },
                audit_summary: AuditSummary {
                    summary: String::new(),
                    records: Vec::new(),
                    high_risk_suppressions: 0,
                    expired_suppressions: Vec::new(),
                    validation_aware_notes: Vec::new(),
                },
                suppression_matches: Vec::new(),
                analysis_limitations: Vec::new(),
                confidence_notes: Vec::new(),
                recommendations: Recommendations {
                    immediate: Vec::new(),
                    short_term: Vec::new(),
                    hardening: Vec::new(),
                    dynamic_validation: Vec::new(),
                },
                suppressions: Vec::new(),
                scan_integrity_notes: Vec::new(),
            })
            .unwrap(),
        )
        .unwrap();

        report.findings.push(agent_skill_guard_core::Finding {
            id: "source.direct_ip".to_string(),
            title: "External reference uses a direct IP address".to_string(),
            issue_code: None,
            title_zh: None,
            category: "source.direct_ip".to_string(),
            severity: agent_skill_guard_core::FindingSeverity::High,
            confidence: agent_skill_guard_core::FindingConfidence::Medium,
            hard_trigger: false,
            evidence_kind: "text_pattern".to_string(),
            location: Some(agent_skill_guard_core::SkillLocation {
                path: "SKILL.md".to_string(),
                line: Some(12),
                column: Some(4),
            }),
            evidence: Vec::new(),
            explanation: "The reference targets a direct IP address.".to_string(),
            explanation_zh: None,
            why_openclaw_specific: "fixture".to_string(),
            prerequisite_context: Vec::new(),
            analyst_notes: Vec::new(),
            remediation: "Use a stable named host.".to_string(),
            recommendation_zh: None,
            suppression_status: "not_suppressed".to_string(),
        });

        let rendered = render_sarif(&report).unwrap();
        let json: Value = serde_json::from_str(&rendered).unwrap();

        assert_eq!(json["version"], "2.1.0");
        assert_eq!(
            json["runs"][0]["tool"]["driver"]["name"],
            "agent-skill-guard"
        );
        assert_eq!(json["runs"][0]["results"][0]["ruleId"], "source.direct_ip");
        assert_eq!(json["runs"][0]["results"][0]["level"], "error");
        assert_eq!(
            json["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]
                ["uri"],
            "SKILL.md"
        );
        assert_eq!(
            json["runs"][0]["results"][0]["properties"]["confidence"],
            "medium"
        );
    }

    #[test]
    fn markdown_and_html_renderers_cover_v2_sections() {
        let report = serde_json::from_str::<ScanReport>(
            &render_json(&ScanReport {
                input_origin: None,
                target: ScanTarget {
                    path: "fixtures/v2/report-demo".to_string(),
                    canonical_path: "fixtures/v2/report-demo".to_string(),
                    target_kind: TargetKind::Workspace,
                },
                scan_mode: "workspace".to_string(),
                files_scanned: 1,
                files_skipped: Vec::new(),
                parse_errors: Vec::new(),
                score: 77,
                verdict: Verdict::Warn,
                blocked: false,
                top_risks: vec!["demo risk".to_string()],
                findings: Vec::new(),
                context_analysis: ContextAnalysis {
                    phase: "phase7_runtime_adapter".to_string(),
                    parsing_summary: "parsed".to_string(),
                    metadata_summary: Some("metadata".to_string()),
                    install_chain_summary: Some("install".to_string()),
                    invocation_summary: None,
                    tool_reachability_summary: None,
                    reachable_tools: Vec::new(),
                    secret_reachability_summary: None,
                    reachable_secret_scopes: Vec::new(),
                    precedence_summary: None,
                    naming_collisions: Vec::new(),
                    host_vs_sandbox_assessment: Some("host vs sandbox".to_string()),
                    prompt_injection_summary: Some("prompt".to_string()),
                    threat_corpus_summary: Some("threat summary".to_string()),
                    sensitive_data_summary: Some("sensitive summary".to_string()),
                    dependency_audit_summary: Some("dependency summary".to_string()),
                    api_classification_summary: Some("api summary".to_string()),
                    source_reputation_summary: Some("source summary".to_string()),
                    openclaw_config_summary: Some("config summary".to_string()),
                    capability_manifest_summary: Some("capability summary".to_string()),
                    companion_doc_audit_summary: Some("companion summary".to_string()),
                    source_identity_summary: Some("identity summary".to_string()),
                    hidden_instruction_summary: Some("hidden summary".to_string()),
                    claims_review_summary: Some("claims summary".to_string()),
                    integrity_snapshot_summary: Some("integrity summary".to_string()),
                    estate_inventory_summary: Some("estate summary".to_string()),
                    agent_package_summary: Some("agent package summary".to_string()),
                    mcp_tool_schema_summary: Some("mcp summary".to_string()),
                    ai_bom_summary: Some("ai bom summary".to_string()),
                    notes: Vec::new(),
                },
                agent_package_index: Default::default(),
                mcp_tool_schema_summary: Default::default(),
                ai_bom: Default::default(),
                attack_paths: Vec::new(),
                path_explanations: Vec::new(),
                prompt_injection_summary: String::new(),
                consequence_summary: ConsequenceAssessment {
                    execution_surface: ExecutionSurface::Uncertain,
                    file_system_consequences: Vec::new(),
                    credential_consequences: Vec::new(),
                    network_consequences: Vec::new(),
                    persistence_consequences: Vec::new(),
                    environment_assumptions: Vec::new(),
                    evidence_nodes: Vec::new(),
                    inferred_notes: Vec::new(),
                    impact_deltas: Vec::new(),
                    summary: "consequence summary".to_string(),
                },
                host_vs_sandbox_split: HostSandboxSplit {
                    host_effects: Vec::new(),
                    sandbox_effects: Vec::new(),
                    blocked_in_sandbox: Vec::new(),
                    residual_sandbox_risks: Vec::new(),
                    summary: "split summary".to_string(),
                },
                runtime_manifest_summary: "manifest summary".to_string(),
                guarded_validation: agent_skill_guard_core::GuardedValidationResult {
                    summary: "guarded validation".to_string(),
                    capability_checks: Vec::new(),
                    constraint_checks: Vec::new(),
                    sandbox_constraint_effects: Vec::new(),
                },
                runtime_facts: Vec::new(),
                runtime_assumption_status: Vec::new(),
                validation_plan: ValidationPlan {
                    summary: String::new(),
                    hooks: Vec::new(),
                },
                validation_hooks: Vec::new(),
                validation_results: Vec::new(),
                path_validation_status: Vec::new(),
                runtime_refinement_notes: Vec::new(),
                constraint_effects: Vec::new(),
                environment_blockers: Vec::new(),
                environment_amplifiers: Vec::new(),
                validation_score_adjustments: Vec::new(),
                corpus_assets_used: Vec::new(),
                dependency_audit_summary: DependencyAuditSummary {
                    summary: "dependency summary".to_string(),
                    manifests_discovered: Vec::new(),
                    lockfile_gaps: Vec::new(),
                    findings_count: 0,
                    notes: Vec::new(),
                },
                api_classification_summary: ApiClassificationSummary {
                    summary: "api summary".to_string(),
                    total_references: 1,
                    category_counts: Default::default(),
                    service_kind_counts: Default::default(),
                    review_needed_count: 0,
                },
                source_reputation_summary: SourceReputationSummary {
                    summary: "source summary".to_string(),
                    suspicious_references: 0,
                    risk_signal_counts: Default::default(),
                    notes: Vec::new(),
                },
                external_references: vec![ExternalReference {
                    reference_id: "ref-001".to_string(),
                    url: "https://github.com/example/project".to_string(),
                    host: "github.com".to_string(),
                    category: agent_skill_guard_core::ExternalReferenceCategory::SourceRepository,
                    service_kind: agent_skill_guard_core::ExternalServiceKind::SourceCodeHost,
                    reputation: agent_skill_guard_core::ExternalReferenceReputation::KnownPlatform,
                    risk_signals: Vec::new(),
                    locations: Vec::new(),
                    evidence_excerpt: "https://github.com/example/project".to_string(),
                    rationale: "fixture".to_string(),
                    provenance: ReferenceClassificationProvenance {
                        taxonomy_entry_id: Some("v2.api.github_repository".to_string()),
                        matched_seed_ids: Vec::new(),
                        asset_sources: vec!["api-taxonomy-v2.yaml".to_string()],
                    },
                }],
                openclaw_config_audit_summary: agent_skill_guard_core::OpenClawConfigAuditSummary {
                    summary: "config summary".to_string(),
                    ..Default::default()
                },
                capability_manifest: agent_skill_guard_core::CapabilityManifestSummary {
                    summary: "capability summary".to_string(),
                    ..Default::default()
                },
                companion_doc_audit_summary: agent_skill_guard_core::CompanionDocAuditSummary {
                    summary: "companion summary".to_string(),
                    ..Default::default()
                },
                source_identity_summary: agent_skill_guard_core::SourceIdentitySummary {
                    summary: "identity summary".to_string(),
                    ..Default::default()
                },
                toxic_flow_summary: Default::default(),
                toxic_flows: Vec::new(),
                hidden_instruction_summary: Default::default(),
                claims_review_summary: Default::default(),
                integrity_snapshot: Default::default(),
                estate_inventory_summary: Default::default(),
                policy_evaluation: Default::default(),
                provenance_notes: Vec::new(),
                confidence_factors: Vec::new(),
                false_positive_mitigations: Vec::new(),
                scoring_summary: ScoringSummary {
                    base_score: 90,
                    compound_uplift: 0,
                    path_uplift: 0,
                    confidence_adjustment: 0,
                    final_score: 77,
                    score_rationale: Vec::new(),
                },
                summary_zh: None,
                openclaw_specific_risk_summary: String::new(),
                scope_resolution_summary: RootResolutionSummary {
                    known_roots: Vec::new(),
                    missing_roots: Vec::new(),
                    scope_notes: Vec::new(),
                    summary: String::new(),
                },
                audit_summary: AuditSummary {
                    summary: String::new(),
                    records: Vec::new(),
                    high_risk_suppressions: 0,
                    expired_suppressions: Vec::new(),
                    validation_aware_notes: Vec::new(),
                },
                suppression_matches: Vec::new(),
                analysis_limitations: Vec::new(),
                confidence_notes: Vec::new(),
                recommendations: Recommendations {
                    immediate: Vec::new(),
                    short_term: Vec::new(),
                    hardening: Vec::new(),
                    dynamic_validation: Vec::new(),
                },
                suppressions: Vec::new(),
                scan_integrity_notes: Vec::new(),
            })
            .unwrap(),
        )
        .unwrap();

        let markdown = render_markdown(&report);
        let html = render_html(&report);

        assert!(markdown.contains("## v2 风险摘要"));
        assert!(markdown.contains("威胁模式库"));
        assert!(markdown.contains("## 外部引用"));
        assert!(html.contains("<!DOCTYPE html>"));
        assert!(html.contains("Agent Skill Guard 安全报告"));
    }
}
