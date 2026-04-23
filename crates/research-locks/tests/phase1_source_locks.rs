use std::fs;

use research_locks::{load_phase1_source_locks, missing_markers, repo_root};

#[test]
fn upstream_research_markers_are_still_present() {
    let locks = load_phase1_source_locks();
    assert!(
        !locks.locks.is_empty(),
        "research/phase1-source-locks.json should not be empty"
    );

    let mut failures = Vec::new();

    for lock in &locks.locks {
        let missing = missing_markers(lock);
        if !missing.is_empty() {
            failures.push(format!(
                "lock {} failed for {}: missing {:?}",
                lock.id, lock.path, missing
            ));
        }
    }

    assert!(
        failures.is_empty(),
        "phase 1 evidence drift detected:\n{}",
        failures.join("\n")
    );
}

#[test]
fn phase1_docs_exist_and_cover_required_topics() {
    let repo = repo_root();
    let checks: [(&str, &[&str]); 4] = [
        (
            "docs/reverse-engineering.md",
            &[
                "# Reverse Engineering",
                "Confirmed Facts",
                "Call Chain",
                "OpenClaw Gap",
            ],
        ),
        (
            "docs/openclaw-current-signals.md",
            &[
                "# OpenClaw Current Signals",
                "Version Baseline",
                "2026.4.20",
                "2026.4.21",
                "GHSA-mj59-h3q9-ghfh",
            ],
        ),
        (
            "docs/openclaw-threat-model.md",
            &[
                "# OpenClaw Threat Model",
                "delegated tool authority",
                "precedence",
                "attack path",
                "Static-analysis limits",
            ],
        ),
        (
            "docs/progress.md",
            &["# Progress", "Phase 1", "Completed", "Next up"],
        ),
    ];

    for (relative, markers) in checks {
        let path = repo.join(relative);
        let content = fs::read_to_string(&path)
            .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));
        for marker in markers {
            assert!(
                content.contains(marker),
                "{} is missing marker {:?}",
                path.display(),
                marker
            );
        }
    }
}

#[test]
fn phase2_docs_and_skeletons_exist_and_cover_required_topics() {
    let repo = repo_root();
    let doc_checks: [(&str, &[&str]); 4] = [
        (
            "docs/design.md",
            &[
                "# Design",
                "CLI-first",
                "9-layer pipeline",
                "RuleSignalSource",
                "JSON is canonical",
            ],
        ),
        (
            "docs/comparison.md",
            &[
                "# Comparison",
                "Direct inheritance",
                "Full rewrites",
                "Increment matrix",
                "not a patch set for a few recent issues",
            ],
        ),
        (
            "docs/refactor-plan.md",
            &[
                "# Refactor Plan",
                "Phase 3",
                "Phase 4",
                "Phase 5",
                "Phase 3 kickoff order",
            ],
        ),
        (
            "docs/progress.md",
            &[
                "## Phase 2",
                "CLI-first",
                "JSON is the source-of-truth report format",
                "Phase 3 kickoff sequence",
            ],
        ),
    ];

    for (relative, markers) in doc_checks {
        let path = repo.join(relative);
        let content = fs::read_to_string(&path)
            .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));
        for marker in markers {
            assert!(
                content.contains(marker),
                "{} is missing marker {:?}",
                path.display(),
                marker
            );
        }
    }

    let skeleton_checks: [(&str, &[&str]); 2] = [
        (
            "schemas/report.schema.json",
            &[
                "\"scan_mode\"",
                "\"context_analysis\"",
                "\"attack_paths\"",
                "\"scan_integrity_notes\"",
            ],
        ),
        (
            "crates/core/src/types.rs",
            &[
                "pub enum TargetKind",
                "pub enum SkillSource",
                "pub enum FindingConfidence",
                "pub enum AttackPathNodeKind",
                "pub struct ScanReport",
            ],
        ),
    ];

    for (relative, markers) in skeleton_checks {
        let path = repo.join(relative);
        let content = fs::read_to_string(&path)
            .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));
        for marker in markers {
            assert!(
                content.contains(marker),
                "{} is missing marker {:?}",
                path.display(),
                marker
            );
        }
    }
}
