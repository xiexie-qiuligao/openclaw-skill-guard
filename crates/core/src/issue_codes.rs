use crate::types::Finding;

pub fn issue_code_for_category(category: &str, id: &str) -> Option<&'static str> {
    if category.starts_with("toxic_flow") {
        Some("OCSG-FLOW-001")
    } else if category.starts_with("mcp.tool_schema") {
        Some("OCSG-MCP-001")
    } else if category.starts_with("mcp.dangerous_command") {
        Some("OCSG-MCP-002")
    } else if category.starts_with("mcp.cross_tool") {
        Some("OCSG-MCP-003")
    } else if category.starts_with("ai_bom") {
        Some("OCSG-AIBOM-001")
    } else if category.starts_with("hidden_instruction") {
        Some("OCSG-HIDDEN-001")
    } else if category.starts_with("claims_review") {
        Some("OCSG-CLAIM-001")
    } else if category.contains("prompt") || id.starts_with("prompt.") {
        Some("OCSG-PROMPT-001")
    } else if category.contains("tool_reachability") {
        Some("OCSG-TOOL-001")
    } else if category.contains("install") {
        Some("OCSG-INSTALL-001")
    } else if category.contains("external_dependency")
        || id.contains("unverifiable")
        || id.contains("remote_dependency")
    {
        Some("OCSG-EXTDEP-001")
    } else if category.contains("financial") {
        Some("OCSG-FIN-001")
    } else if category.contains("system_service") {
        Some("OCSG-SYSTEM-001")
    } else if category.contains("credential") {
        Some("OCSG-CRED-001")
    } else if category.contains("third_party_content") {
        Some("OCSG-CONTENT-001")
    } else if category.starts_with("dependency.") {
        Some("OCSG-DEP-001")
    } else if category.starts_with("source.") {
        Some("OCSG-SOURCE-001")
    } else if category.starts_with("openclaw_config") || category.contains("config") {
        Some("OCSG-CONFIG-001")
    } else if category.starts_with("capability") {
        Some("OCSG-CAP-001")
    } else if category.starts_with("companion") {
        Some("OCSG-DOC-001")
    } else if category.starts_with("source_identity") {
        Some("OCSG-ID-001")
    } else {
        None
    }
}

pub fn apply_issue_codes(findings: &mut [Finding]) {
    for finding in findings {
        if finding.issue_code.is_none() {
            finding.issue_code =
                issue_code_for_category(&finding.category, &finding.id).map(str::to_string);
        }
    }
}
