use crate::dependency_audit::DependencyAuditAnalysis;
use crate::localization::debug_label_zh;
use crate::types::{
    AgentPackageIndexSummary, AiBom, ExternalReference, IntegritySnapshot, SourceIdentitySummary,
};

pub fn build_ai_bom(
    package_index: &AgentPackageIndexSummary,
    external_references: &[ExternalReference],
    dependency_audit: &DependencyAuditAnalysis,
    source_identity: &SourceIdentitySummary,
    integrity_snapshot: &IntegritySnapshot,
) -> AiBom {
    let packages = package_index
        .packages
        .iter()
        .map(|package| {
            format!(
                "{}: {} ({})",
                debug_label_zh(&package.package_kind),
                package
                    .name
                    .clone()
                    .unwrap_or_else(|| "unnamed".to_string()),
                safe_path(&package.source_path)
            )
        })
        .collect::<Vec<_>>();

    let tool_surfaces = package_index
        .packages
        .iter()
        .flat_map(|package| {
            package
                .surface
                .tools
                .iter()
                .map(move |tool| format!("{}: {}", safe_path(&package.source_path), tool))
        })
        .collect::<Vec<_>>();

    let mcp_servers = package_index
        .packages
        .iter()
        .filter(|package| format!("{:?}", package.package_kind) == "McpConfig")
        .map(|package| safe_path(&package.source_path))
        .collect::<Vec<_>>();

    let commands = package_index
        .packages
        .iter()
        .flat_map(|package| {
            package
                .surface
                .commands
                .iter()
                .map(move |command| format!("{}: {}", safe_path(&package.source_path), command))
        })
        .collect::<Vec<_>>();

    let env_and_config = package_index
        .packages
        .iter()
        .flat_map(|package| {
            package
                .surface
                .env
                .iter()
                .map(move |env| format!("{}: {}", safe_path(&package.source_path), env))
        })
        .collect::<Vec<_>>();

    let external_services = external_references
        .iter()
        .map(|reference| format!("{}: {}", reference.host, reference.url))
        .collect::<Vec<_>>();

    let dependencies = dependency_audit
        .summary
        .manifests_discovered
        .iter()
        .chain(dependency_audit.summary.lockfile_gaps.iter())
        .map(|value| safe_path(value))
        .collect::<Vec<_>>();

    let source_identities = source_identity
        .identity_surfaces
        .iter()
        .chain(source_identity.signals.iter().map(|signal| &signal.summary))
        .cloned()
        .collect::<Vec<_>>();

    let integrity_digests = integrity_snapshot
        .skill_file_digests
        .iter()
        .map(|digest| format!("{}: {}", safe_path(&digest.path), digest.sha256))
        .collect::<Vec<_>>();

    let mut review_questions = Vec::new();
    if !mcp_servers.is_empty() {
        review_questions.push("这些 MCP server command 是否来自可信来源并已固定版本？".to_string());
    }
    if !env_and_config.is_empty() {
        review_questions.push("这些 env/config 是否会把凭据暴露给不必要的工具面？".to_string());
    }
    if !external_services.is_empty() {
        review_questions.push("外部服务、下载源和文档链接是否与 package 身份一致？".to_string());
    }
    if review_questions.is_empty() {
        review_questions.push("package 身份、权限、来源和完整性摘要是否符合预期？".to_string());
    }

    AiBom {
        summary: format!(
            "AI BOM contains {} package(s), {} tool surface item(s), {} external service reference(s).",
            packages.len(),
            tool_surfaces.len(),
            external_services.len()
        ),
        summary_zh: format!(
            "AI BOM 汇总 {} 个 package、{} 个工具面、{} 个外部服务引用。",
            packages.len(),
            tool_surfaces.len(),
            external_services.len()
        ),
        packages,
        tool_surfaces,
        mcp_servers,
        commands,
        env_and_config,
        external_services,
        dependencies,
        source_identities,
        integrity_digests,
        review_questions,
    }
}

fn safe_path(path: &str) -> String {
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
