use std::collections::BTreeMap;

use crate::types::{
    CollisionConfidence, EvidenceKind, EvidenceNode, Finding, FindingConfidence,
    FindingSeverity, ParsedSkill, PrecedenceCollision, PrecedenceScope, RootResolutionSummary,
    ScopeLimitationNote, SkillLocation, SkillSource, TargetKind,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrecedenceAnalysis {
    pub summary: String,
    pub collisions: Vec<PrecedenceCollision>,
    pub root_resolution: RootResolutionSummary,
    pub findings: Vec<Finding>,
}

pub fn analyze_precedence(skills: &[ParsedSkill], target_kind: TargetKind) -> PrecedenceAnalysis {
    let mut by_name: BTreeMap<String, Vec<&ParsedSkill>> = BTreeMap::new();
    let root_resolution = build_root_resolution(skills, target_kind);

    for skill in skills {
        if let Some(name) = skill.descriptor.name.as_deref() {
            by_name.entry(name.to_ascii_lowercase()).or_default().push(skill);
        }
        for slug in &skill.descriptor.slug_candidates {
            by_name.entry(format!("slug:{slug}")).or_default().push(skill);
        }
    }

    let mut collisions = Vec::new();
    let mut findings = Vec::new();

    for (key, skills) in by_name {
        if skills.len() < 2 {
            continue;
        }

        let collision = PrecedenceCollision {
            skill_name: key.clone(),
            collision_kind: if key.starts_with("slug:") { "slug_collision" } else { "name_collision" }.to_string(),
            winning_source: choose_preferred_source(&skills),
            losing_source: choose_secondary_source(&skills),
            paths: skills.iter().map(|skill| skill.skill_file.clone()).collect(),
            limited_by_scope: !root_resolution.missing_roots.is_empty(),
            confidence: if root_resolution.missing_roots.is_empty() {
                CollisionConfidence::ConfirmedWithinScannedRoots
            } else if matches!(target_kind, TargetKind::SkillsRoot | TargetKind::Workspace | TargetKind::OpenClawHome) {
                CollisionConfidence::PossibleScopeLimited
            } else {
                CollisionConfidence::Unresolved
            },
            notes: root_resolution
                .scope_notes
                .iter()
                .map(|note| note.message.clone())
                .collect(),
        };

        findings.push(make_collision_finding(&collision));
        collisions.push(collision);
    }

    let summary = if collisions.is_empty() {
        if matches!(target_kind, TargetKind::SkillsRoot | TargetKind::Workspace | TargetKind::OpenClawHome) {
            "No local naming collisions were detected in the scanned scope.".to_string()
        } else {
            "Precedence analysis is limited by the current scan scope; no local naming collisions were detected.".to_string()
        }
    } else {
        format!(
            "Detected {} local naming collision(s); precedence confidence is refined by scanned and missing roots.",
            collisions.len()
        )
    };

    PrecedenceAnalysis {
        summary,
        collisions,
        root_resolution,
        findings,
    }
}

fn build_root_resolution(skills: &[ParsedSkill], target_kind: TargetKind) -> RootResolutionSummary {
    let mut known_roots: Vec<PrecedenceScope> = skills
        .iter()
        .map(|skill| PrecedenceScope {
            source: skill.source,
            path: skill.skill_root.clone(),
            present: true,
        })
        .collect();
    known_roots.sort_by(|left, right| left.path.cmp(&right.path));
    known_roots.dedup_by(|left, right| left.path == right.path && left.source == right.source);

    let mut missing_roots = Vec::new();
    for (label, source) in [
        ("workspace", SkillSource::Workspace),
        ("personal_agents", SkillSource::PersonalAgents),
        ("managed", SkillSource::Managed),
        ("bundled", SkillSource::Bundled),
        ("plugin_extra_dir", SkillSource::PluginExtraDir),
    ] {
        if !known_roots.iter().any(|root| root.source == source) {
            missing_roots.push(label.to_string());
        }
    }

    if matches!(target_kind, TargetKind::OpenClawHome) {
        missing_roots.retain(|root| root != "personal_agents");
    }

    let mut scope_notes = Vec::new();
    if !missing_roots.is_empty() {
        scope_notes.push(ScopeLimitationNote {
            message: format!(
                "The following OpenClaw roots were not observed in the current scan and can affect precedence resolution: {}.",
                missing_roots.join(", ")
            ),
        });
    }
    if matches!(target_kind, TargetKind::File | TargetKind::SkillDir) {
        scope_notes.push(ScopeLimitationNote {
            message: "Single-file or single-skill scans cannot fully resolve precedence across personal, managed, bundled, plugin, and workspace roots.".to_string(),
        });
    }

    let summary = if missing_roots.is_empty() {
        "Precedence resolution covered all expected roots visible to the current scan.".to_string()
    } else {
        format!(
            "Observed {} root(s); precedence remains incomplete until these roots are scanned: {}.",
            known_roots.len(),
            missing_roots.join(", ")
        )
    };

    RootResolutionSummary {
        known_roots,
        missing_roots,
        scope_notes,
        summary,
    }
}

fn choose_preferred_source(skills: &[&ParsedSkill]) -> SkillSource {
    let mut ranked: Vec<SkillSource> = skills.iter().map(|skill| skill.source).collect();
    ranked.sort_by_key(source_rank);
    ranked.first().copied().unwrap_or(SkillSource::Unknown)
}

fn choose_secondary_source(skills: &[&ParsedSkill]) -> SkillSource {
    let mut ranked: Vec<SkillSource> = skills.iter().map(|skill| skill.source).collect();
    ranked.sort_by_key(source_rank);
    ranked.get(1).copied().unwrap_or(SkillSource::Unknown)
}

fn source_rank(source: &SkillSource) -> usize {
    match source {
        SkillSource::Workspace => 0,
        SkillSource::ProjectAgents => 1,
        SkillSource::PersonalAgents => 2,
        SkillSource::Managed => 3,
        SkillSource::Bundled => 4,
        SkillSource::ExtraDir => 5,
        SkillSource::PluginExtraDir => 6,
        SkillSource::ClawHubWorkspaceInstall => 7,
        SkillSource::Unknown => 8,
    }
}

fn make_collision_finding(collision: &PrecedenceCollision) -> Finding {
    let location = SkillLocation {
        path: collision.paths.first().cloned().unwrap_or_default(),
        line: Some(1),
        column: None,
    };
    Finding {
        id: "context.precedence.name_collision".to_string(),
        title: "Potential skill naming collision in scanned scope".to_string(),
        category: "precedence".to_string(),
        severity: FindingSeverity::Medium,
        confidence: FindingConfidence::High,
        hard_trigger: false,
        evidence_kind: "precedence_collision".to_string(),
        location: Some(location.clone()),
        evidence: vec![EvidenceNode {
            kind: EvidenceKind::PrecedenceCollision,
            location,
            excerpt: collision.skill_name.clone(),
            direct: true,
        }],
        explanation: format!("Multiple skills in the scanned scope share the same resolved name or slug candidate `{}`.", collision.skill_name),
        why_openclaw_specific: "OpenClaw merges skills from multiple roots with source precedence, so same-name collisions can become trusted-name hijack or shadowing problems.".to_string(),
        prerequisite_context: vec!["Collision analysis is limited to the current scan scope unless all relevant skill roots are present.".to_string()],
        analyst_notes: vec![format!(
            "Collision confidence is {:?}; precedence analysis avoids inventing global winner/loser claims outside the scanned roots.",
            collision.confidence
        )],
        remediation: "Rename colliding skills or explicitly review how they will resolve under OpenClaw precedence rules.".to_string(),
        suppression_status: "not_suppressed".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use crate::skill_parse::parse_skill_file;
    use crate::types::TargetKind;

    use super::analyze_precedence;

    #[test]
    fn detects_basic_name_collision() {
        let first = parse_skill_file(Path::new("workspace/a/SKILL.md"), "---\nname: Demo\n---\nBody", Vec::new());
        let second = parse_skill_file(Path::new("bundled/b/SKILL.md"), "---\nname: Demo\n---\nBody", Vec::new());
        let analysis = analyze_precedence(&[first, second], TargetKind::SkillsRoot);
        assert!(analysis
            .collisions
            .iter()
            .any(|collision| collision.collision_kind == "name_collision"));
        assert!(analysis
            .findings
            .iter()
            .any(|finding| finding.id == "context.precedence.name_collision"));
        assert!(!analysis.root_resolution.known_roots.is_empty());
    }

    #[test]
    fn scope_limitation_is_reported_when_roots_are_missing() {
        let first = parse_skill_file(Path::new("workspace/a/SKILL.md"), "---\nname: Demo\n---\nBody", Vec::new());
        let analysis = analyze_precedence(&[first], TargetKind::File);
        assert!(!analysis.root_resolution.missing_roots.is_empty());
        assert!(!analysis.root_resolution.scope_notes.is_empty());
    }
}
