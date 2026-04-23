use std::{fs, path::PathBuf};

use serde_json::Value;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap()
}

fn read_example(path: &str) -> String {
    let raw = fs::read_to_string(repo_root().join(path)).unwrap();
    raw.trim_start_matches('\u{feff}').to_string()
}

fn assert_no_local_path_leak(text: &str) {
    for needle in ["D:/", "C:/", "\\\\?\\", "/Users/", "Users/29345", "漏扫skill"] {
        assert!(
            !text.contains(needle),
            "example output still contains local path marker `{needle}`"
        );
    }
}

#[test]
fn canonical_json_example_matches_v2_shape() {
    let text = read_example("examples/reports/v2-report-demo.json");
    assert_no_local_path_leak(&text);

    let json: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(json["scan_mode"], "skill_dir");
    assert!(json["findings"].as_array().unwrap().len() >= 5);
    assert!(json["corpus_assets_used"].as_array().unwrap().len() >= 4);
    assert!(json["external_references"].as_array().unwrap().len() >= 2);
    assert!(json["dependency_audit_summary"]["findings_count"].as_u64().unwrap() >= 1);
    assert!(
        json["context_analysis"]["threat_corpus_summary"]
            .as_str()
            .unwrap()
            .contains("Threat corpus")
    );
    assert!(
        json["context_analysis"]["sensitive_data_summary"]
            .as_str()
            .unwrap()
            .contains("Sensitive-data corpus")
    );
}

#[test]
fn sarif_example_is_parseable_and_mapped_from_findings() {
    let text = read_example("examples/reports/v2-report-demo.sarif");
    assert_no_local_path_leak(&text);

    let json: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(json["version"], "2.1.0");
    assert_eq!(json["runs"][0]["tool"]["driver"]["name"], "openclaw-skill-guard");
    assert!(json["runs"][0]["results"].as_array().unwrap().len() >= 5);
    assert_eq!(
        json["runs"][0]["tool"]["driver"]["rules"][0]["shortDescription"]["text"]
            .is_string(),
        true
    );
}

#[test]
fn markdown_and_html_examples_cover_v2_sections() {
    let markdown = read_example("examples/reports/v2-report-demo.md");
    assert_no_local_path_leak(&markdown);
    assert!(markdown.contains("## V2 Summaries"));
    assert!(markdown.contains("## Findings"));
    assert!(markdown.contains("## Validation And Consequence"));
    assert!(markdown.contains("## External References"));
    assert!(markdown.contains("## Score And Provenance"));

    let html = read_example("examples/reports/v2-report-demo.html");
    assert_no_local_path_leak(&html);
    assert!(html.contains("<!DOCTYPE html>"));
    assert!(html.contains("## V2 Summaries"));
    assert!(html.contains("## Findings"));
    assert!(html.contains("## External References"));
}
