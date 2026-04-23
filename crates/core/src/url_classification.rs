use std::collections::BTreeMap;

use regex::Regex;

use crate::corpus::{host_pattern_matches, BuiltinCorpora, ReputationSeedKind};
use crate::types::{
    ApiClassificationSummary, EvidenceKind, EvidenceNode, ExternalReference,
    ExternalReferenceCategory, ExternalReferenceReputation, ExternalRiskSignal,
    ExternalServiceKind, Finding, FindingConfidence, FindingSeverity, ProvenanceNote,
    ReferenceClassificationProvenance, SkillLocation, SourceReputationSummary, TextArtifact,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UrlClassificationAnalysis {
    pub api_summary: ApiClassificationSummary,
    pub reputation_summary: SourceReputationSummary,
    pub external_references: Vec<ExternalReference>,
    pub findings: Vec<Finding>,
    pub provenance_notes: Vec<ProvenanceNote>,
}

pub fn analyze_external_references(
    documents: &[TextArtifact],
    corpora: &BuiltinCorpora,
) -> UrlClassificationAnalysis {
    let extracted = extract_references(documents, corpora);
    let mut category_counts = BTreeMap::<String, usize>::new();
    let mut service_kind_counts = BTreeMap::<String, usize>::new();
    let mut risk_signal_counts = BTreeMap::<String, usize>::new();
    let mut suspicious_references = 0usize;
    let mut findings = Vec::new();
    let mut provenance_notes = Vec::new();

    for reference in &extracted {
        *category_counts
            .entry(category_label(reference.category).to_string())
            .or_insert(0) += 1;
        *service_kind_counts
            .entry(service_kind_label(reference.service_kind).to_string())
            .or_insert(0) += 1;
        if reference.reputation == ExternalReferenceReputation::Suspicious {
            suspicious_references += 1;
        }
        for signal in &reference.risk_signals {
            *risk_signal_counts
                .entry(risk_signal_label(*signal).to_string())
                .or_insert(0) += 1;
        }
        findings.extend(build_reference_findings(reference));
        if reference.provenance.taxonomy_entry_id.is_some()
            || !reference.provenance.matched_seed_ids.is_empty()
        {
            provenance_notes.push(ProvenanceNote {
                subject_id: reference.reference_id.clone(),
                subject_kind: "external_reference".to_string(),
                source_layer: "corpus_asset".to_string(),
                evidence_sources: {
                    let mut sources = Vec::new();
                    if let Some(taxonomy) = &reference.provenance.taxonomy_entry_id {
                        sources.push(taxonomy.clone());
                    }
                    sources.extend(reference.provenance.matched_seed_ids.clone());
                    sources
                },
                inferred_sources: Vec::new(),
                recent_signal_class: "v2_external_reference_classification".to_string(),
                long_term_pattern: "source, api, and domain risk classification".to_string(),
                note: format!(
                    "External reference classification used taxonomy/seeds from {}.",
                    reference.provenance.asset_sources.join(", ")
                ),
            });
        }
    }

    let review_needed_count = extracted
        .iter()
        .filter(|reference| reference.reputation == ExternalReferenceReputation::ReviewNeeded)
        .count();

    UrlClassificationAnalysis {
        api_summary: ApiClassificationSummary {
            summary: if extracted.is_empty() {
                "No external references were extracted from scanned text artifacts.".to_string()
            } else {
                format!(
                    "Extracted {} external reference(s) across scanned text artifacts.",
                    extracted.len()
                )
            },
            total_references: extracted.len(),
            category_counts,
            service_kind_counts,
            review_needed_count,
        },
        reputation_summary: SourceReputationSummary {
            summary: if extracted.is_empty() {
                "No source or domain reputation hints were generated.".to_string()
            } else {
                format!(
                    "Generated reputation hints for {} external reference(s), with {} marked suspicious.",
                    extracted.len(),
                    suspicious_references
                )
            },
            suspicious_references,
            risk_signal_counts,
            notes: vec![
                "Reputation hints are local and explainable; they are not online trust verdicts.".to_string(),
                "Signals come from taxonomy matches, seed hits, and URL structure heuristics.".to_string(),
            ],
        },
        external_references: extracted,
        findings,
        provenance_notes,
    }
}

fn extract_references(documents: &[TextArtifact], corpora: &BuiltinCorpora) -> Vec<ExternalReference> {
    let url_regex = Regex::new(r#"https?://[^\s"'`<>()]+"#).unwrap();
    let mut refs = BTreeMap::<String, ExternalReference>::new();
    let mut next_reference_id = 1usize;

    for document in documents {
        for (line_number, line) in document.content.lines().enumerate() {
            for matched in url_regex.find_iter(line) {
                let cleaned = clean_url(matched.as_str());
                let Some(host) = extract_host(&cleaned) else {
                    continue;
                };
                let location = SkillLocation {
                    path: document.path.clone(),
                    line: Some(line_number + 1),
                    column: Some(matched.start() + 1),
                };
                let (category, service_kind, reputation, risk_signals, rationale, provenance) =
                    classify_reference(&cleaned, &host, corpora);
                let reference_id = format!("ref-{next_reference_id:03}");
                let entry = refs.entry(cleaned.clone()).or_insert_with(|| ExternalReference {
                    reference_id,
                    url: cleaned.clone(),
                    host: host.clone(),
                    category,
                    service_kind,
                    reputation,
                    risk_signals,
                    locations: Vec::new(),
                    evidence_excerpt: line.trim().to_string(),
                    rationale,
                    provenance,
                });
                if entry.locations.is_empty() {
                    next_reference_id += 1;
                }
                entry.locations.push(location);
            }
        }
    }

    refs.into_values().collect()
}

fn classify_reference(
    url: &str,
    host: &str,
    corpora: &BuiltinCorpora,
) -> (
    ExternalReferenceCategory,
    ExternalServiceKind,
    ExternalReferenceReputation,
    Vec<ExternalRiskSignal>,
    String,
    ReferenceClassificationProvenance,
) {
    let mut matched_seed_ids = Vec::new();
    let mut risk_signals = Vec::new();
    let mut taxonomy_entry_id = None;
    let mut asset_sources = vec!["api-taxonomy-v2.yaml".to_string(), "reputation-seeds-v2.yaml".to_string()];

    let raw_path = extract_path(url);

    for seed in &corpora.reputation_seeds {
        let matched = match seed.seed_kind {
            ReputationSeedKind::ExactHost => host == seed.value,
            ReputationSeedKind::Suffix => host.ends_with(&seed.value),
            ReputationSeedKind::Tld => host.ends_with(&seed.value),
            ReputationSeedKind::PathFragment => raw_path.contains(&seed.value),
            ReputationSeedKind::RawHost => host == seed.value,
            ReputationSeedKind::ShortlinkHost => host == seed.value,
            ReputationSeedKind::DynamicDnsSuffix => host.ends_with(&seed.value),
        };
        if matched {
            matched_seed_ids.push(seed.id.clone());
            match seed.seed_kind {
                ReputationSeedKind::ShortlinkHost => risk_signals.push(ExternalRiskSignal::Shortlink),
                ReputationSeedKind::DynamicDnsSuffix => {
                    risk_signals.push(ExternalRiskSignal::DynamicDnsSuffix)
                }
                ReputationSeedKind::Tld => risk_signals.push(ExternalRiskSignal::SuspiciousTld),
                _ => risk_signals.push(ExternalRiskSignal::KnownSuspiciousSeed),
            }
        }
    }

    if is_pure_ip(host) {
        risk_signals.push(ExternalRiskSignal::PureIp);
    }
    if !url.to_ascii_lowercase().starts_with("https://") {
        risk_signals.push(ExternalRiskSignal::NonHttps);
    }
    if raw_path.contains("/raw/") {
        risk_signals.push(ExternalRiskSignal::RawDownloadPath);
    }
    if host == "raw.githubusercontent.com" || host == "gist.githubusercontent.com" {
        risk_signals.push(ExternalRiskSignal::RawDownloadHost);
    }
    if looks_like_file_download(url) {
        risk_signals.push(ExternalRiskSignal::DirectFileDownload);
    }

    let mut category = ExternalReferenceCategory::Unknown;
    let mut service_kind = ExternalServiceKind::Unknown;
    let mut reputation = ExternalReferenceReputation::ReviewNeeded;
    let mut rationale = "No taxonomy entry matched; review is recommended.".to_string();

    if is_pure_ip(host) {
        category = ExternalReferenceCategory::DirectIp;
        reputation = ExternalReferenceReputation::Suspicious;
        rationale = "The URL host is a direct IP address rather than a named domain.".to_string();
    } else if risk_signals.contains(&ExternalRiskSignal::Shortlink) {
        category = ExternalReferenceCategory::Shortlink;
        reputation = ExternalReferenceReputation::Suspicious;
        rationale = "The URL host is a known shortlink provider that obscures the final destination.".to_string();
    } else if risk_signals.contains(&ExternalRiskSignal::DynamicDnsSuffix) {
        category = ExternalReferenceCategory::DynamicDns;
        reputation = ExternalReferenceReputation::Suspicious;
        rationale = "The URL host matches a dynamic DNS or tunnel suffix.".to_string();
    } else if is_auth_like_path(&raw_path) {
        category = ExternalReferenceCategory::AuthEndpoint;
        service_kind = ExternalServiceKind::GeneralApi;
        rationale = "The URL path looks like an authentication or token endpoint.".to_string();
    }

    for entry in &corpora.api_taxonomy {
        let host_match = entry
            .host_patterns
            .iter()
            .any(|pattern| host_pattern_matches(pattern, host));
        let url_match = entry
            .url_patterns
            .iter()
            .any(|pattern| !pattern.trim().is_empty() && pattern != "/" && url.contains(pattern));
        if host_match || (entry.host_patterns.is_empty() && url_match) {
            category = parse_category(&entry.category);
            service_kind = parse_service_kind(&entry.service_kind);
            reputation = parse_reputation(&entry.reputation_hint);
            rationale = format!(
                "Matched API taxonomy entry `{}` with category `{}` and service kind `{}`.",
                entry.id, entry.category, entry.service_kind
            );
            taxonomy_entry_id = Some(entry.id.clone());
            break;
        }
    }

    if matches!(category, ExternalReferenceCategory::Unknown) && looks_like_file_download(url) {
        category = ExternalReferenceCategory::FileDownload;
        rationale = "The URL path looks like a direct file download.".to_string();
    }
    if matches!(category, ExternalReferenceCategory::Unknown) && raw_path.contains("/raw/") {
        category = ExternalReferenceCategory::RawContent;
        rationale = "The URL path suggests raw content retrieval outside a repository view.".to_string();
    }
    if matches!(category, ExternalReferenceCategory::Unknown) && looks_like_api_endpoint(host, &raw_path) {
        category = ExternalReferenceCategory::ApiEndpoint;
        service_kind = ExternalServiceKind::GeneralApi;
        rationale =
            "The host or path looks like a generic API endpoint but did not match a known taxonomy entry."
                .to_string();
    }

    if risk_signals
        .iter()
        .any(|signal| matches!(signal, ExternalRiskSignal::KnownSuspiciousSeed | ExternalRiskSignal::SuspiciousTld))
    {
        reputation = ExternalReferenceReputation::Suspicious;
    }

    risk_signals.sort_by_key(|signal| risk_signal_label(*signal));
    risk_signals.dedup();
    asset_sources.sort();
    asset_sources.dedup();

    (
        category,
        service_kind,
        reputation,
        risk_signals,
        rationale,
        ReferenceClassificationProvenance {
            taxonomy_entry_id,
            matched_seed_ids,
            asset_sources,
        },
    )
}

fn build_reference_findings(reference: &ExternalReference) -> Vec<Finding> {
    let mut findings = Vec::new();
    let location = reference.locations.first().cloned();
    let mut add = |id: &str, title: &str, severity: FindingSeverity, explanation: &str| {
        findings.push(Finding {
            id: id.to_string(),
            title: title.to_string(),
            category: id.to_string(),
            severity,
            confidence: FindingConfidence::Medium,
            hard_trigger: false,
            evidence_kind: "text_pattern".to_string(),
            location: location.clone(),
            evidence: vec![EvidenceNode {
                kind: EvidenceKind::TextPattern,
                location: location.clone().unwrap_or(SkillLocation {
                    path: reference.host.clone(),
                    line: None,
                    column: None,
                }),
                excerpt: reference.evidence_excerpt.clone(),
                direct: true,
            }],
            explanation: explanation.to_string(),
            why_openclaw_specific: "URLs and service references in OpenClaw skills shape install flows, external fetch behavior, and source trust narratives.".to_string(),
            prerequisite_context: vec!["The external reference was extracted directly from scanned text content.".to_string()],
            analyst_notes: build_reference_notes(reference),
            remediation: "Review the referenced source, prefer stable trusted hosts, and avoid opaque or weak-trust fetch targets in install or execution flows.".to_string(),
            suppression_status: "not_suppressed".to_string(),
        });
    };

    for signal in &reference.risk_signals {
        match signal {
            ExternalRiskSignal::Shortlink => add(
                "source.shortlink",
                "External reference uses a shortlink host",
                FindingSeverity::Medium,
                "The reference resolves through a shortlink host, which hides the final destination during review.",
            ),
            ExternalRiskSignal::RawDownloadHost | ExternalRiskSignal::RawDownloadPath => add(
                "source.raw_content_fetch",
                "External reference points at raw content",
                FindingSeverity::Medium,
                "The reference points at raw content rather than a reviewed repository or documentation surface.",
            ),
            ExternalRiskSignal::PureIp => add(
                "source.direct_ip",
                "External reference uses a direct IP address",
                FindingSeverity::High,
                "The reference targets a direct IP address, which weakens source transparency and reviewability.",
            ),
            ExternalRiskSignal::DynamicDnsSuffix => add(
                "source.dynamic_dns",
                "External reference uses a dynamic DNS or tunnel host",
                FindingSeverity::High,
                "The reference targets a dynamic DNS or tunnel host that often represents unstable or temporary exposure.",
            ),
            ExternalRiskSignal::SuspiciousTld => add(
                "source.suspicious_tld",
                "External reference uses a suspicious TLD",
                FindingSeverity::Medium,
                "The reference host uses a TLD that is commonly treated as a weak local reputation signal.",
            ),
            ExternalRiskSignal::KnownSuspiciousSeed => add(
                "source.known_suspicious_seed",
                "External reference matched a suspicious source seed",
                FindingSeverity::High,
                "The reference matched a local suspicious-source seed from the v2 reputation corpus.",
            ),
            _ => {}
        }
    }

    if reference.category == ExternalReferenceCategory::ApiEndpoint
        && reference.reputation == ExternalReferenceReputation::ReviewNeeded
    {
        add(
            "api.review_needed",
            "API endpoint needs source review",
            FindingSeverity::Low,
            "The reference looks like an API endpoint but did not match a trusted or well-known taxonomy entry.",
        );
    }

    findings
}

fn build_reference_notes(reference: &ExternalReference) -> Vec<String> {
    let mut notes = vec![format!("classification rationale: {}", reference.rationale)];
    if let Some(taxonomy_entry_id) = &reference.provenance.taxonomy_entry_id {
        notes.push(format!("taxonomy match: {taxonomy_entry_id}"));
    }
    if !reference.provenance.matched_seed_ids.is_empty() {
        notes.push(format!(
            "reputation seeds: {}",
            reference.provenance.matched_seed_ids.join(", ")
        ));
    }
    notes
}

fn category_label(value: ExternalReferenceCategory) -> &'static str {
    match value {
        ExternalReferenceCategory::SourceRepository => "source_repository",
        ExternalReferenceCategory::Documentation => "documentation",
        ExternalReferenceCategory::RawContent => "raw_content",
        ExternalReferenceCategory::ApiEndpoint => "api_endpoint",
        ExternalReferenceCategory::AuthEndpoint => "auth_endpoint",
        ExternalReferenceCategory::PackageRegistry => "package_registry",
        ExternalReferenceCategory::ObjectStorage => "object_storage",
        ExternalReferenceCategory::FileDownload => "file_download",
        ExternalReferenceCategory::Shortlink => "shortlink",
        ExternalReferenceCategory::DynamicDns => "dynamic_dns",
        ExternalReferenceCategory::DirectIp => "direct_ip",
        ExternalReferenceCategory::Unknown => "unknown",
    }
}

fn service_kind_label(value: ExternalServiceKind) -> &'static str {
    match value {
        ExternalServiceKind::SourceCodeHost => "source_code_host",
        ExternalServiceKind::PackageEcosystem => "package_ecosystem",
        ExternalServiceKind::CloudPlatform => "cloud_platform",
        ExternalServiceKind::AiService => "ai_service",
        ExternalServiceKind::GeneralApi => "general_api",
        ExternalServiceKind::ContentDelivery => "content_delivery",
        ExternalServiceKind::Unknown => "unknown",
    }
}

fn risk_signal_label(value: ExternalRiskSignal) -> &'static str {
    match value {
        ExternalRiskSignal::Shortlink => "shortlink",
        ExternalRiskSignal::RawDownloadHost => "raw_download_host",
        ExternalRiskSignal::RawDownloadPath => "raw_download_path",
        ExternalRiskSignal::PureIp => "pure_ip",
        ExternalRiskSignal::DynamicDnsSuffix => "dynamic_dns_suffix",
        ExternalRiskSignal::SuspiciousTld => "suspicious_tld",
        ExternalRiskSignal::NonHttps => "non_https",
        ExternalRiskSignal::DirectFileDownload => "direct_file_download",
        ExternalRiskSignal::KnownSuspiciousSeed => "known_suspicious_seed",
    }
}

fn parse_category(value: &str) -> ExternalReferenceCategory {
    match value {
        "source_repository" => ExternalReferenceCategory::SourceRepository,
        "documentation" => ExternalReferenceCategory::Documentation,
        "raw_content" => ExternalReferenceCategory::RawContent,
        "api_endpoint" => ExternalReferenceCategory::ApiEndpoint,
        "auth_endpoint" => ExternalReferenceCategory::AuthEndpoint,
        "package_registry" => ExternalReferenceCategory::PackageRegistry,
        "object_storage" => ExternalReferenceCategory::ObjectStorage,
        "file_download" => ExternalReferenceCategory::FileDownload,
        "shortlink" => ExternalReferenceCategory::Shortlink,
        "dynamic_dns" => ExternalReferenceCategory::DynamicDns,
        "direct_ip" => ExternalReferenceCategory::DirectIp,
        _ => ExternalReferenceCategory::Unknown,
    }
}

fn parse_service_kind(value: &str) -> ExternalServiceKind {
    match value {
        "source_code_host" => ExternalServiceKind::SourceCodeHost,
        "package_ecosystem" => ExternalServiceKind::PackageEcosystem,
        "cloud_platform" => ExternalServiceKind::CloudPlatform,
        "ai_service" => ExternalServiceKind::AiService,
        "general_api" => ExternalServiceKind::GeneralApi,
        "content_delivery" => ExternalServiceKind::ContentDelivery,
        _ => ExternalServiceKind::Unknown,
    }
}

fn parse_reputation(value: &str) -> ExternalReferenceReputation {
    match value {
        "trusted_infrastructure" => ExternalReferenceReputation::TrustedInfrastructure,
        "known_platform" => ExternalReferenceReputation::KnownPlatform,
        "suspicious" => ExternalReferenceReputation::Suspicious,
        _ => ExternalReferenceReputation::ReviewNeeded,
    }
}

fn clean_url(url: &str) -> String {
    url.trim_end_matches(|ch: char| [',', ';', ')', ']', '>', '"', '\''].contains(&ch))
        .to_string()
}

fn extract_host(url: &str) -> Option<String> {
    let scheme_split = url.find("://")?;
    let without_scheme = &url[scheme_split + 3..];
    let authority = without_scheme
        .split(['/', '?', '#'])
        .next()
        .unwrap_or_default();
    let host = authority
        .rsplit('@')
        .next()
        .unwrap_or_default()
        .split(':')
        .next()
        .unwrap_or_default()
        .trim()
        .trim_matches('[')
        .trim_matches(']');
    if host.is_empty() {
        return None;
    }
    Some(host.to_ascii_lowercase())
}

fn extract_path(url: &str) -> String {
    let scheme_split = url.find("://");
    if let Some(index) = scheme_split {
        let remainder = &url[index + 3..];
        let mut parts = remainder.splitn(2, '/');
        let _authority = parts.next();
        let tail = parts.next().unwrap_or_default();
        return format!("/{}", tail);
    }
    "/".to_string()
}

fn is_pure_ip(host: &str) -> bool {
    host.split('.').count() == 4
        && host
            .split('.')
            .all(|part| !part.is_empty() && part.parse::<u8>().is_ok())
}

fn looks_like_file_download(url: &str) -> bool {
    let lowered = url.to_ascii_lowercase();
    [
        ".zip",
        ".tar",
        ".tar.gz",
        ".tgz",
        ".exe",
        ".dll",
        ".msi",
        ".whl",
        ".crate",
        ".deb",
        ".rpm",
    ]
    .iter()
    .any(|suffix| lowered.contains(suffix))
        || lowered.contains("/releases/download/")
}

fn is_auth_like_path(path: &str) -> bool {
    let lowered = path.to_ascii_lowercase();
    lowered.contains("/oauth")
        || lowered.contains("/authorize")
        || lowered.contains("/token")
        || lowered.contains("/login")
}

fn looks_like_api_endpoint(host: &str, path: &str) -> bool {
    let lowered_host = host.to_ascii_lowercase();
    let lowered_path = path.to_ascii_lowercase();
    lowered_host.starts_with("api.")
        || lowered_host.contains(".api.")
        || lowered_path.starts_with("/v1/")
        || lowered_path.starts_with("/v2/")
        || lowered_path.contains("/api/")
}

#[cfg(test)]
mod tests {
    use crate::corpus::load_builtin_corpora;
    use crate::types::{ExternalReferenceCategory, ExternalReferenceReputation, ExternalRiskSignal, TextArtifact};

    use super::analyze_external_references;

    #[test]
    fn classifies_common_reference_types() {
        let corpora = load_builtin_corpora().unwrap();
        let docs = vec![TextArtifact {
            path: "repo/SKILL.md".to_string(),
            content: "Docs https://docs.github.com/en\nRepo https://github.com/openai/openai-cookbook\nRaw https://raw.githubusercontent.com/user/repo/main/install.sh\nAPI https://api.openai.com/v1/chat/completions".to_string(),
        }];

        let analysis = analyze_external_references(&docs, &corpora);

        assert!(analysis.external_references.iter().any(|item| item.category == ExternalReferenceCategory::Documentation));
        assert!(analysis.external_references.iter().any(|item| item.category == ExternalReferenceCategory::SourceRepository));
        assert!(analysis.external_references.iter().any(|item| item.category == ExternalReferenceCategory::RawContent));
        assert!(analysis.external_references.iter().any(|item| item.category == ExternalReferenceCategory::ApiEndpoint));
    }

    #[test]
    fn flags_suspicious_sources() {
        let corpora = load_builtin_corpora().unwrap();
        let docs = vec![TextArtifact {
            path: "repo/SKILL.md".to_string(),
            content: "https://bit.ly/demo https://10.0.0.7/payload https://demo.ngrok.io/install https://malicious.top/file".to_string(),
        }];

        let analysis = analyze_external_references(&docs, &corpora);

        assert!(analysis
            .external_references
            .iter()
            .any(|item| item.risk_signals.contains(&ExternalRiskSignal::Shortlink)));
        assert!(analysis
            .external_references
            .iter()
            .any(|item| item.risk_signals.contains(&ExternalRiskSignal::PureIp)));
        assert!(analysis
            .external_references
            .iter()
            .any(|item| item.risk_signals.contains(&ExternalRiskSignal::DynamicDnsSuffix)));
        assert!(analysis
            .external_references
            .iter()
            .any(|item| item.risk_signals.contains(&ExternalRiskSignal::SuspiciousTld)));
        assert!(analysis
            .external_references
            .iter()
            .any(|item| item.reputation == ExternalReferenceReputation::Suspicious));
    }

    #[test]
    fn benign_github_repo_does_not_create_suspicious_source_finding() {
        let corpora = load_builtin_corpora().unwrap();
        let docs = vec![TextArtifact {
            path: "repo/README.md".to_string(),
            content: "Project home: https://github.com/example/project".to_string(),
        }];

        let analysis = analyze_external_references(&docs, &corpora);

        assert!(analysis.findings.is_empty());
    }

    #[test]
    fn unknown_api_endpoint_is_marked_review_needed() {
        let corpora = load_builtin_corpora().unwrap();
        let docs = vec![TextArtifact {
            path: "repo/SKILL.md".to_string(),
            content: "Use https://api.unknown-example.dev/v1/run for requests".to_string(),
        }];

        let analysis = analyze_external_references(&docs, &corpora);

        assert!(analysis
            .findings
            .iter()
            .any(|finding| finding.id == "api.review_needed"));
    }
}
