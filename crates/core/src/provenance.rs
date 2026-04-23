use std::collections::BTreeMap;

use crate::instruction::InstructionAnalysis;
use crate::precedence::PrecedenceAnalysis;
use crate::types::{
    AttackPath, ConfidenceFactor, FalsePositiveMitigation, Finding, FindingConfidence,
    ProvenanceNote, SkillLocation, TargetKind,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProvenanceAnalysis {
    pub findings: Vec<Finding>,
    pub attack_paths: Vec<AttackPath>,
    pub provenance_notes: Vec<ProvenanceNote>,
    pub confidence_factors: Vec<ConfidenceFactor>,
    pub false_positive_mitigations: Vec<FalsePositiveMitigation>,
    pub confidence_notes: Vec<String>,
}

pub fn refine_findings_and_paths(
    findings: &[Finding],
    attack_paths: &[AttackPath],
    instructions: &InstructionAnalysis,
    precedence: &PrecedenceAnalysis,
    target_kind: TargetKind,
) -> ProvenanceAnalysis {
    let mut updated_findings = findings.to_vec();
    let mut updated_paths = attack_paths.to_vec();
    let mut provenance_notes = Vec::new();
    let mut confidence_factors = Vec::new();
    let mut mitigations = Vec::new();
    let segments_by_line = build_instruction_map(instructions);

    for finding in &mut updated_findings {
        provenance_notes.push(build_finding_provenance(finding));
        let mut delta = 0;

        if matches!(
            finding.evidence_kind.as_str(),
            "structured_metadata" | "tool_dispatch" | "secret_reference"
        ) && finding.evidence.iter().any(|node| node.direct)
        {
            confidence_factors.push(ConfidenceFactor {
                subject_id: finding.id.clone(),
                factor: "direct_structured_or_sensitive_signal".to_string(),
                delta: 1,
                rationale: "Direct metadata, tool-dispatch, or sensitive-path evidence increases trust in the finding.".to_string(),
            });
            delta += 1;
        }

        if finding.category == "threat_corpus" || finding.category == "sensitive_corpus" {
            confidence_factors.push(ConfidenceFactor {
                subject_id: finding.id.clone(),
                factor: "typed_corpus_provenance".to_string(),
                delta: 1,
                rationale: "Typed corpus entries carry explicit provenance and false-positive notes, which makes the finding easier to audit and explain.".to_string(),
            });
            delta += 1;
        }

        if finding.id.starts_with("dependency.") || finding.id.starts_with("source.") {
            confidence_factors.push(ConfidenceFactor {
                subject_id: finding.id.clone(),
                factor: "local_explainable_signal".to_string(),
                delta: 1,
                rationale: "The finding is derived from local manifests, URLs, or typed seeds rather than an opaque online reputation score.".to_string(),
            });
            delta += 1;
        }

        if is_example_or_quote_context(
            finding.location.as_ref(),
            &segments_by_line,
            &finding.evidence,
        ) {
            mitigations.push(FalsePositiveMitigation {
                subject_id: finding.id.clone(),
                mitigation_kind: "example_or_quote_context".to_string(),
                delta: -1,
                rationale: "The signal appears in an example-like or code-fence context, so confidence is reduced unless stronger runtime evidence exists.".to_string(),
            });
            delta -= 1;
        }

        if is_benign_localhost_context(&finding.evidence) {
            mitigations.push(FalsePositiveMitigation {
                subject_id: finding.id.clone(),
                mitigation_kind: "benign_localhost_or_rpc".to_string(),
                delta: -1,
                rationale: "Localhost/RPC management wording can be legitimate when not combined with coercion, secrets, or egress.".to_string(),
            });
            delta -= 1;
        }

        if is_benign_child_process_context(&finding.evidence) {
            mitigations.push(FalsePositiveMitigation {
                subject_id: finding.id.clone(),
                mitigation_kind: "benign_child_process_reference".to_string(),
                delta: -1,
                rationale: "A child_process or exec reference inside example-like or descriptive text is weaker than direct coercive tool guidance.".to_string(),
            });
            delta -= 1;
        }

        if is_legitimate_package_manager_install(finding) {
            mitigations.push(FalsePositiveMitigation {
                subject_id: finding.id.clone(),
                mitigation_kind: "pinned_package_manager_install".to_string(),
                delta: -1,
                rationale: "Pinned package-manager install guidance is still part of the setup surface, but it is weaker than remote download-and-execute behavior.".to_string(),
            });
            delta -= 1;
        }

        if finding.category == "tool_reachability"
            && finding
                .evidence
                .iter()
                .all(|node| node.excerpt.to_ascii_lowercase().contains("exec"))
            && finding.why_openclaw_specific.contains("metadata")
        {
            confidence_factors.push(ConfidenceFactor {
                subject_id: finding.id.clone(),
                factor: "tool_reachability_metadata_context".to_string(),
                delta: 1,
                rationale: "Reachability inferred from explicit metadata or command wiring is stronger than a loose text mention.".to_string(),
            });
            delta += 1;
        }

        if precedence.root_resolution.missing_roots.len() > 0 && finding.category == "precedence" {
            mitigations.push(FalsePositiveMitigation {
                subject_id: finding.id.clone(),
                mitigation_kind: "scope_incomplete".to_string(),
                delta: -1,
                rationale: "Precedence confidence is reduced because not all relevant roots are present in the scan.".to_string(),
            });
            delta -= 1;
        }

        adjust_confidence(&mut finding.confidence, delta);
    }

    for path in &mut updated_paths {
        provenance_notes.push(build_path_provenance(path));
        let mut delta = 0;
        if path.evidence_nodes.len() >= 2 && path.evidence_nodes.iter().any(|node| node.direct) {
            confidence_factors.push(ConfidenceFactor {
                subject_id: path.path_id.clone(),
                factor: "multiple_evidence_nodes".to_string(),
                delta: 1,
                rationale: "The path is backed by multiple evidence nodes instead of a single weak connector.".to_string(),
            });
            delta += 1;
        }
        if path.path_type == "trust_hijack"
            && (precedence.root_resolution.missing_roots.len() > 0
                || matches!(target_kind, TargetKind::File | TargetKind::SkillDir))
        {
            mitigations.push(FalsePositiveMitigation {
                subject_id: path.path_id.clone(),
                mitigation_kind: "scope_limited_trust_hijack".to_string(),
                delta: -1,
                rationale: "Trusted-name hijack inference is weaker when global root resolution is incomplete.".to_string(),
            });
            delta -= 1;
        }
        if path.path_type == "secret_exfiltration_potential"
            && path.inferred_nodes.len() > path.evidence_nodes.len()
        {
            mitigations.push(FalsePositiveMitigation {
                subject_id: path.path_id.clone(),
                mitigation_kind: "inference_heavier_than_evidence".to_string(),
                delta: -1,
                rationale: "The path requires additional runtime assumptions before it becomes a confirmed exfiltration path.".to_string(),
            });
            delta -= 1;
        }
        adjust_confidence(&mut path.confidence, delta);
    }

    let mut confidence_notes = vec![
        "Confidence refinement now considers structured metadata evidence, example-like context, localhost/RPC benign scenarios, and scope incompleteness.".to_string(),
        "False-positive mitigation reduces confidence instead of silently removing findings or paths.".to_string(),
    ];
    if precedence.root_resolution.missing_roots.len() > 0 {
        confidence_notes.push("Precedence-related confidence was reduced where missing roots prevented stronger global resolution.".to_string());
    }

    ProvenanceAnalysis {
        findings: updated_findings,
        attack_paths: updated_paths,
        provenance_notes,
        confidence_factors,
        false_positive_mitigations: mitigations,
        confidence_notes,
    }
}

fn build_instruction_map(instructions: &InstructionAnalysis) -> BTreeMap<(String, usize), String> {
    instructions
        .segments
        .iter()
        .filter_map(|segment| {
            segment.location.line.map(|line| {
                (
                    (segment.location.path.clone(), line),
                    format!("{:?}", segment.source),
                )
            })
        })
        .collect()
}

fn build_finding_provenance(finding: &Finding) -> ProvenanceNote {
    ProvenanceNote {
        subject_id: finding.id.clone(),
        subject_kind: "finding".to_string(),
        source_layer: finding.category.clone(),
        evidence_sources: finding_provenance_sources(finding),
        inferred_sources: finding.prerequisite_context.clone(),
        recent_signal_class: classify_recent_signal(&finding.category),
        long_term_pattern: classify_long_term_pattern(&finding.category, &finding.id),
        note: finding_provenance_note(finding),
    }
}

fn build_path_provenance(path: &AttackPath) -> ProvenanceNote {
    ProvenanceNote {
        subject_id: path.path_id.clone(),
        subject_kind: "attack_path".to_string(),
        source_layer: path.path_type.clone(),
        evidence_sources: path
            .evidence_nodes
            .iter()
            .map(|node| format!("{:?}", node.kind))
            .collect(),
        inferred_sources: path.inferred_nodes.clone(),
        recent_signal_class: "attack_path_explanation".to_string(),
        long_term_pattern: format!("compound {}", path.path_type),
        note: "Attack path provenance keeps direct evidence separate from connectors that remain inferred.".to_string(),
    }
}

fn classify_recent_signal(category: &str) -> String {
    match category {
        "prompt_injection" => "prompt_runtime_hardening".to_string(),
        "invocation_policy" | "tool_reachability" => "delegated_tool_authority".to_string(),
        "precedence" => "precedence_and_scope".to_string(),
        "secret_reachability" => "secret_injection_and_host_context".to_string(),
        "threat_corpus" => "typed_threat_corpus".to_string(),
        "sensitive_corpus" => "typed_sensitive_corpus".to_string(),
        "execution" | "obfuscation" | "destructive" => "baseline_execution_surface".to_string(),
        _ if category.starts_with("dependency.") || category == "dependency_audit" => {
            "dependency_source_review".to_string()
        }
        _ if category.starts_with("source.") || category.starts_with("api.") => {
            "external_reference_review".to_string()
        }
        _ => "scanner_boundary_and_fp_control".to_string(),
    }
}

fn classify_long_term_pattern(category: &str, id: &str) -> String {
    if id.contains("install") {
        "install path asymmetry and setup-time remote execution".to_string()
    } else if category == "prompt_injection" {
        "instruction-level coercion against tool authority or trust boundaries".to_string()
    } else if category == "precedence" {
        "multi-root naming collision and trust hijack".to_string()
    } else if category == "secret_reachability" {
        "secret-bearing local runtime context".to_string()
    } else if category == "threat_corpus" {
        "corpus-backed instruction, tool, or agent-context risk".to_string()
    } else if category == "sensitive_corpus" {
        "inline secret or credential material packaged with skill content".to_string()
    } else if id.starts_with("dependency.") {
        "dependency manifest drift and supply-chain source review".to_string()
    } else if id.starts_with("source.") || id.starts_with("api.") {
        "external service trust, source credibility, and raw-fetch review".to_string()
    } else {
        "direct execution or control-surface exposure".to_string()
    }
}

fn finding_provenance_sources(finding: &Finding) -> Vec<String> {
    let mut sources = vec![finding.evidence_kind.clone()];
    for note in &finding.analyst_notes {
        if note.starts_with("corpus entry:")
            || note.starts_with("asset:")
            || note.starts_with("taxonomy match:")
            || note.starts_with("reputation seeds:")
            || note.starts_with("sensitive category:")
        {
            sources.push(note.clone());
        }
    }
    sources
}

fn finding_provenance_note(finding: &Finding) -> String {
    if finding.category == "threat_corpus" {
        "Threat corpus provenance records the exact typed entry, asset file, and adapted reference that produced this additive finding."
            .to_string()
    } else if finding.category == "sensitive_corpus" {
        "Sensitive-data corpus provenance records the exact typed entry and whether the analyzer treated the match as high-value inline material or example-like review content."
            .to_string()
    } else if finding.id.starts_with("dependency.") {
        "Dependency provenance records which local manifest, lockfile, or install-chain artifact produced the explainable supply-chain signal."
            .to_string()
    } else if finding.id.starts_with("source.") || finding.id.starts_with("api.") {
        "Source/API provenance records the local URL, taxonomy match, and seed-based hints behind the external-reference finding."
            .to_string()
    } else {
        "Finding provenance records where the signal originated and which longer-lived risk family it belongs to.".to_string()
    }
}

fn is_example_or_quote_context(
    location: Option<&SkillLocation>,
    instructions: &BTreeMap<(String, usize), String>,
    evidence: &[crate::types::EvidenceNode],
) -> bool {
    if evidence.iter().any(|node| {
        let lowered = node.excerpt.to_ascii_lowercase();
        lowered.contains("for example")
            || lowered.starts_with("example:")
            || lowered.contains("\"example\"")
            || lowered.contains("'example'")
    }) {
        return true;
    }
    if let Some(location) = location {
        if let Some(line) = location.line {
            if let Some(source) = instructions.get(&(location.path.clone(), line)) {
                return source.contains("CodeFence");
            }
        }
    }
    false
}

fn is_benign_localhost_context(evidence: &[crate::types::EvidenceNode]) -> bool {
    evidence.iter().any(|node| {
        let lowered = node.excerpt.to_ascii_lowercase();
        (lowered.contains("localhost") || lowered.contains("127.0.0.1") || lowered.contains("rpc"))
            && !lowered.contains("upload")
            && !lowered.contains("token")
            && !lowered.contains("secret")
    })
}

fn is_benign_child_process_context(evidence: &[crate::types::EvidenceNode]) -> bool {
    evidence.iter().any(|node| {
        let lowered = node.excerpt.to_ascii_lowercase();
        (lowered.contains("child_process")
            || lowered.contains("exec(")
            || lowered.contains("process.spawn"))
            && !lowered.contains("run without asking")
            && !lowered.contains("upload")
            && !lowered.contains("secret")
    })
}

fn is_legitimate_package_manager_install(finding: &Finding) -> bool {
    if finding.category != "supply_chain_risk" {
        return false;
    }
    finding.evidence.iter().any(|node| {
        let lowered = node.excerpt.to_ascii_lowercase();
        let pinned_npm = lowered.contains("npm install") && lowered.contains('@');
        let pinned_go = lowered.contains("go install") && lowered.contains("@v");
        let pinned_uv = lowered.contains("uv tool install") && (lowered.contains("==") || lowered.contains('@'));
        let pinned_brew = lowered.contains("brew install") && !lowered.contains("http");
        (pinned_npm || pinned_go || pinned_uv || pinned_brew)
            && !lowered.contains("curl")
            && !lowered.contains("wget")
            && !lowered.contains("invoke-webrequest")
            && !lowered.contains("| bash")
    })
}

fn adjust_confidence(confidence: &mut FindingConfidence, delta: i32) {
    let level = match confidence {
        FindingConfidence::Low => 0_i32,
        FindingConfidence::Medium => 1,
        FindingConfidence::High => 2,
        FindingConfidence::InferredCompound => 1,
    };
    let next = (level + delta).clamp(0, 2);
    *confidence = match next {
        0 => FindingConfidence::Low,
        1 => FindingConfidence::Medium,
        _ => FindingConfidence::High,
    };
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use crate::attack_paths::build_attack_paths;
    use crate::compound_rules::evaluate_compound_rules;
    use crate::install::analyze_install_chain;
    use crate::instruction::extract_instruction_segments;
    use crate::invocation::analyze_invocation_policy;
    use crate::precedence::analyze_precedence;
    use crate::prompt_injection::analyze_instruction_segments;
    use crate::reachability::{analyze_secret_reachability, analyze_tool_reachability};
    use crate::skill_parse::parse_skill_file;
    use crate::types::{FindingConfidence, TargetKind};

    use super::refine_findings_and_paths;

    #[test]
    fn example_context_reduces_confidence() {
        let skill = parse_skill_file(
            Path::new("demo/SKILL.md"),
            "---\nname: Demo\n---\nExample:\n```bash\nuse exec\n```",
            Vec::new(),
        );
        let instructions = extract_instruction_segments(&skill);
        let prompt = analyze_instruction_segments(&instructions.segments);
        let install = analyze_install_chain(&skill);
        let invocation = analyze_invocation_policy(&skill);
        let tools = analyze_tool_reachability(&skill);
        let secrets = analyze_secret_reachability(&skill);
        let precedence = analyze_precedence(&[skill.clone()], TargetKind::File);
        let compounds = evaluate_compound_rules(
            &[skill.clone()],
            &instructions,
            &prompt,
            &install,
            &invocation,
            &tools,
            &secrets,
            &precedence,
        );
        let paths = build_attack_paths(
            &[skill],
            &prompt,
            &install,
            &invocation,
            &tools,
            &secrets,
            &precedence,
            &compounds,
        );

        let analysis = refine_findings_and_paths(
            &prompt.findings,
            &paths.paths,
            &instructions,
            &precedence,
            TargetKind::File,
        );

        assert!(analysis
            .false_positive_mitigations
            .iter()
            .any(|item| item.mitigation_kind == "example_or_quote_context"));
    }

    #[test]
    fn direct_evidence_can_stay_high_confidence() {
        let skill = parse_skill_file(
            Path::new("demo/SKILL.md"),
            "---\ncommand-dispatch: tool\ncommand-tool: exec\n---\nBody",
            Vec::new(),
        );
        let invocation = analyze_invocation_policy(&skill);
        let instructions = extract_instruction_segments(&skill);
        let precedence = analyze_precedence(&[skill], TargetKind::File);

        let analysis = refine_findings_and_paths(
            &invocation.findings,
            &[],
            &instructions,
            &precedence,
            TargetKind::File,
        );

        assert!(analysis
            .findings
            .iter()
            .any(|finding| finding.confidence == FindingConfidence::High));
    }

    #[test]
    fn localhost_prompt_context_is_downgraded() {
        let skill = parse_skill_file(
            Path::new("demo/SKILL.md"),
            "---\nname: Demo\n---\nUse browser to inspect localhost RPC status on 127.0.0.1:8545.",
            Vec::new(),
        );
        let instructions = extract_instruction_segments(&skill);
        let prompt = analyze_instruction_segments(&instructions.segments);
        let precedence = analyze_precedence(&[skill], TargetKind::File);

        let analysis =
            refine_findings_and_paths(&prompt.findings, &[], &instructions, &precedence, TargetKind::File);

        assert!(analysis
            .false_positive_mitigations
            .iter()
            .any(|item| item.mitigation_kind == "benign_localhost_or_rpc"));
    }

    #[test]
    fn pinned_install_instruction_is_downgraded() {
        let skill = parse_skill_file(
            Path::new("demo/SKILL.md"),
            "---\nname: Demo\n---\nInstall with npm install demo-cli@1.2.3",
            Vec::new(),
        );
        let install = analyze_install_chain(&skill);
        let instructions = extract_instruction_segments(&skill);
        let precedence = analyze_precedence(&[skill], TargetKind::File);

        let analysis =
            refine_findings_and_paths(&install.findings, &[], &instructions, &precedence, TargetKind::File);

        assert!(analysis
            .false_positive_mitigations
            .iter()
            .any(|item| item.mitigation_kind == "pinned_package_manager_install"));
    }
}
