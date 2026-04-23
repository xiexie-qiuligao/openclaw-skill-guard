use regex::Regex;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::types::{CorpusAssetUsage, CorpusProvenance, FindingSeverity};

const THREAT_CORPUS_ASSET: &str = include_str!("../assets/threat-corpus-v2.yaml");
const SENSITIVE_DATA_CORPUS_ASSET: &str = include_str!("../assets/sensitive-data-corpus-v2.yaml");
const API_TAXONOMY_ASSET: &str = include_str!("../assets/api-taxonomy-v2.yaml");
const REPUTATION_SEEDS_ASSET: &str = include_str!("../assets/reputation-seeds-v2.yaml");

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuiltinCorpora {
    pub threat_patterns: Vec<ThreatCorpusEntry>,
    pub sensitive_data_patterns: Vec<SensitiveDataCorpusEntry>,
    pub api_taxonomy: Vec<ApiTaxonomyEntry>,
    pub reputation_seeds: Vec<ReputationSeedEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CorpusMatcher {
    Regex { pattern: String },
    Substring { value: String },
    HostPattern { value: String },
}

impl CorpusMatcher {
    pub fn matches_text(&self, text: &str) -> Result<bool, regex::Error> {
        match self {
            CorpusMatcher::Regex { pattern } => Ok(Regex::new(pattern)?.is_match(text)),
            CorpusMatcher::Substring { value } => Ok(text.contains(value)),
            CorpusMatcher::HostPattern { value } => Ok(host_pattern_matches(value, text)),
        }
    }

    fn validate(&self) -> Result<(), regex::Error> {
        if let CorpusMatcher::Regex { pattern } = self {
            Regex::new(pattern)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThreatCorpusEntry {
    pub id: String,
    pub category: String,
    pub matcher: CorpusMatcher,
    pub description: String,
    pub severity_hint: Option<FindingSeverity>,
    #[serde(default)]
    pub false_positive_notes: Vec<String>,
    pub provenance: CorpusProvenance,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SensitiveDataCorpusEntry {
    pub id: String,
    pub category: String,
    pub matcher: CorpusMatcher,
    pub description: String,
    pub severity_hint: Option<FindingSeverity>,
    #[serde(default)]
    pub false_positive_notes: Vec<String>,
    pub provenance: CorpusProvenance,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiTaxonomyEntry {
    pub id: String,
    pub category: String,
    #[serde(default)]
    pub host_patterns: Vec<String>,
    #[serde(default)]
    pub url_patterns: Vec<String>,
    pub service_kind: String,
    pub description: String,
    pub reputation_hint: String,
    pub provenance: CorpusProvenance,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReputationSeedKind {
    ExactHost,
    Suffix,
    Tld,
    PathFragment,
    RawHost,
    ShortlinkHost,
    DynamicDnsSuffix,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReputationSeedEntry {
    pub id: String,
    pub seed_kind: ReputationSeedKind,
    pub value: String,
    pub risk_hint: String,
    pub description: String,
    #[serde(default)]
    pub false_positive_notes: Vec<String>,
    pub provenance: CorpusProvenance,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum CorpusLoadError {
    #[error("failed to parse {asset_name}: {message}")]
    Parse {
        asset_name: String,
        message: String,
    },
    #[error("duplicate id `{id}` in {asset_name}")]
    DuplicateId { asset_name: String, id: String },
    #[error("invalid matcher in {asset_name} for `{id}`: {message}")]
    InvalidMatcher {
        asset_name: String,
        id: String,
        message: String,
    },
    #[error("invalid api taxonomy entry `{id}` in {asset_name}: {message}")]
    InvalidApiTaxonomy {
        asset_name: String,
        id: String,
        message: String,
    },
    #[error("invalid reputation seed `{id}` in {asset_name}: {message}")]
    InvalidReputationSeed {
        asset_name: String,
        id: String,
        message: String,
    },
}

pub fn load_builtin_corpora() -> Result<BuiltinCorpora, CorpusLoadError> {
    let threat_patterns = parse_asset::<ThreatCorpusEntry>("threat-corpus-v2.yaml", THREAT_CORPUS_ASSET)?;
    let sensitive_data_patterns =
        parse_asset::<SensitiveDataCorpusEntry>("sensitive-data-corpus-v2.yaml", SENSITIVE_DATA_CORPUS_ASSET)?;
    let api_taxonomy = parse_api_taxonomy("api-taxonomy-v2.yaml", API_TAXONOMY_ASSET)?;
    let reputation_seeds = parse_reputation_seeds("reputation-seeds-v2.yaml", REPUTATION_SEEDS_ASSET)?;

    Ok(BuiltinCorpora {
        threat_patterns,
        sensitive_data_patterns,
        api_taxonomy,
        reputation_seeds,
    })
}

pub fn corpus_assets_used(corpora: &BuiltinCorpora) -> Vec<CorpusAssetUsage> {
    vec![
        CorpusAssetUsage {
            asset_name: "threat-corpus-v2.yaml".to_string(),
            entry_count: corpora.threat_patterns.len(),
            source_refs: unique_source_refs(
                corpora
                    .threat_patterns
                    .iter()
                    .map(|entry| entry.provenance.source_ref.as_str()),
            ),
            notes: vec!["Threat pattern asset loaded from compile-time YAML.".to_string()],
        },
        CorpusAssetUsage {
            asset_name: "sensitive-data-corpus-v2.yaml".to_string(),
            entry_count: corpora.sensitive_data_patterns.len(),
            source_refs: unique_source_refs(
                corpora
                    .sensitive_data_patterns
                    .iter()
                    .map(|entry| entry.provenance.source_ref.as_str()),
            ),
            notes: vec!["Sensitive data corpus loaded from compile-time YAML.".to_string()],
        },
        CorpusAssetUsage {
            asset_name: "api-taxonomy-v2.yaml".to_string(),
            entry_count: corpora.api_taxonomy.len(),
            source_refs: unique_source_refs(
                corpora
                    .api_taxonomy
                    .iter()
                    .map(|entry| entry.provenance.source_ref.as_str()),
            ),
            notes: vec!["API taxonomy loaded from compile-time YAML.".to_string()],
        },
        CorpusAssetUsage {
            asset_name: "reputation-seeds-v2.yaml".to_string(),
            entry_count: corpora.reputation_seeds.len(),
            source_refs: unique_source_refs(
                corpora
                    .reputation_seeds
                    .iter()
                    .map(|entry| entry.provenance.source_ref.as_str()),
            ),
            notes: vec!["Reputation seeds loaded from compile-time YAML.".to_string()],
        },
    ]
}

pub fn host_pattern_matches(pattern: &str, host: &str) -> bool {
    let pattern = pattern.trim().to_ascii_lowercase();
    let host = host.trim().to_ascii_lowercase();
    if pattern.is_empty() || host.is_empty() {
        return false;
    }
    if let Some(suffix) = pattern.strip_prefix("*.") {
        return host == suffix || host.ends_with(&format!(".{suffix}"));
    }
    host == pattern
}

fn parse_asset<T>(asset_name: &str, input: &str) -> Result<Vec<T>, CorpusLoadError>
where
    T: DeserializeOwned + ValidateAssetEntry,
{
    let entries: Vec<T> = serde_yaml::from_str(input).map_err(|err| CorpusLoadError::Parse {
        asset_name: asset_name.to_string(),
        message: err.to_string(),
    })?;

    let mut seen = std::collections::BTreeSet::new();
    for entry in &entries {
        if !seen.insert(entry.id().to_string()) {
            return Err(CorpusLoadError::DuplicateId {
                asset_name: asset_name.to_string(),
                id: entry.id().to_string(),
            });
        }
        entry.validate(asset_name)?;
    }

    Ok(entries)
}

fn parse_api_taxonomy(asset_name: &str, input: &str) -> Result<Vec<ApiTaxonomyEntry>, CorpusLoadError> {
    parse_asset(asset_name, input)
}

fn parse_reputation_seeds(
    asset_name: &str,
    input: &str,
) -> Result<Vec<ReputationSeedEntry>, CorpusLoadError> {
    parse_asset(asset_name, input)
}

fn unique_source_refs<'a>(refs: impl Iterator<Item = &'a str>) -> Vec<String> {
    let mut seen = std::collections::BTreeSet::new();
    for source_ref in refs {
        if !source_ref.trim().is_empty() {
            seen.insert(source_ref.to_string());
        }
    }
    seen.into_iter().collect()
}

trait ValidateAssetEntry {
    fn id(&self) -> &str;
    fn validate(&self, asset_name: &str) -> Result<(), CorpusLoadError>;
}

impl ValidateAssetEntry for ThreatCorpusEntry {
    fn id(&self) -> &str {
        &self.id
    }

    fn validate(&self, asset_name: &str) -> Result<(), CorpusLoadError> {
        self.matcher
            .validate()
            .map_err(|err| CorpusLoadError::InvalidMatcher {
                asset_name: asset_name.to_string(),
                id: self.id.clone(),
                message: err.to_string(),
            })
    }
}

impl ValidateAssetEntry for SensitiveDataCorpusEntry {
    fn id(&self) -> &str {
        &self.id
    }

    fn validate(&self, asset_name: &str) -> Result<(), CorpusLoadError> {
        self.matcher
            .validate()
            .map_err(|err| CorpusLoadError::InvalidMatcher {
                asset_name: asset_name.to_string(),
                id: self.id.clone(),
                message: err.to_string(),
            })
    }
}

impl ValidateAssetEntry for ApiTaxonomyEntry {
    fn id(&self) -> &str {
        &self.id
    }

    fn validate(&self, asset_name: &str) -> Result<(), CorpusLoadError> {
        if self.host_patterns.is_empty() && self.url_patterns.is_empty() {
            return Err(CorpusLoadError::InvalidApiTaxonomy {
                asset_name: asset_name.to_string(),
                id: self.id.clone(),
                message: "entry must define at least one host pattern or URL pattern".to_string(),
            });
        }
        Ok(())
    }
}

impl ValidateAssetEntry for ReputationSeedEntry {
    fn id(&self) -> &str {
        &self.id
    }

    fn validate(&self, asset_name: &str) -> Result<(), CorpusLoadError> {
        if self.value.trim().is_empty() {
            return Err(CorpusLoadError::InvalidReputationSeed {
                asset_name: asset_name.to_string(),
                id: self.id.clone(),
                message: "seed value must not be empty".to_string(),
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{
        corpus_assets_used, host_pattern_matches, load_builtin_corpora, parse_asset, CorpusMatcher,
        SensitiveDataCorpusEntry, ThreatCorpusEntry,
    };

    #[test]
    fn builtin_corpora_load_successfully() {
        let corpora = load_builtin_corpora().unwrap();

        assert!(!corpora.threat_patterns.is_empty());
        assert!(!corpora.sensitive_data_patterns.is_empty());
        assert!(!corpora.api_taxonomy.is_empty());
        assert!(!corpora.reputation_seeds.is_empty());
    }

    #[test]
    fn corpus_assets_used_is_stable() {
        let corpora = load_builtin_corpora().unwrap();
        let assets = corpus_assets_used(&corpora);

        assert_eq!(assets.len(), 4);
        assert_eq!(assets[0].asset_name, "threat-corpus-v2.yaml");
        assert!(assets.iter().all(|asset| asset.entry_count > 0));
    }

    #[test]
    fn duplicate_ids_fail_validation() {
        let yaml = r#"
- id: duplicate
  category: prompt
  matcher:
    kind: regex
    pattern: "(?i)ignore previous"
  description: first
  provenance:
    source_name: test
    source_kind: first_party
    source_ref: test
    notes: []
- id: duplicate
  category: prompt
  matcher:
    kind: substring
    value: "ignore previous"
  description: second
  provenance:
    source_name: test
    source_kind: first_party
    source_ref: test
    notes: []
"#;

        let error = parse_asset::<ThreatCorpusEntry>("test.yaml", yaml).unwrap_err();
        assert!(error.to_string().contains("duplicate id"));
    }

    #[test]
    fn invalid_regex_fails_validation() {
        let yaml = r#"
- id: bad-regex
  category: prompt
  matcher:
    kind: regex
    pattern: "("
  description: invalid
  provenance:
    source_name: test
    source_kind: first_party
    source_ref: test
    notes: []
"#;

        let error = parse_asset::<ThreatCorpusEntry>("test.yaml", yaml).unwrap_err();
        assert!(error.to_string().contains("invalid matcher"));
    }

    #[test]
    fn matcher_supports_regex_and_substring() {
        assert!(CorpusMatcher::Regex {
            pattern: "(?i)ignore previous".to_string()
        }
        .matches_text("Please ignore previous instructions")
        .unwrap());

        assert!(CorpusMatcher::Substring {
            value: "sk-".to_string()
        }
        .matches_text("token=sk-123456789")
        .unwrap());
    }

    #[test]
    fn host_pattern_supports_suffix_matching() {
        assert!(host_pattern_matches("*.github.com", "raw.github.com"));
        assert!(host_pattern_matches("github.com", "github.com"));
        assert!(!host_pattern_matches("*.github.com", "githubusercontent.com"));
    }

    #[test]
    fn sensitive_entry_yaml_shape_is_supported() {
        let yaml = r#"
- id: fake-openai
  category: api_key
  matcher:
    kind: substring
    value: "sk-fake"
  description: fake key
  severity_hint: high
  false_positive_notes:
    - docs-only
  provenance:
    source_name: test
    source_kind: adapted_reference
    source_ref: local
    notes:
      - synthetic
"#;

        let entries = parse_asset::<SensitiveDataCorpusEntry>("test.yaml", yaml).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].id, "fake-openai");
    }
}
