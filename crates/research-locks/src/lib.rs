use std::fs;
use std::path::{Path, PathBuf};

use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct Phase1SourceLocks {
    pub locks: Vec<SourceLock>,
}

#[derive(Debug, Deserialize)]
pub struct SourceLock {
    pub id: String,
    pub path: String,
    pub must_contain: Vec<String>,
}

pub fn repo_root() -> PathBuf {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest_dir
        .parent()
        .and_then(Path::parent)
        .expect("crate should live under repo_root/crates/<name>")
        .to_path_buf()
}

pub fn load_phase1_source_locks() -> Phase1SourceLocks {
    let path = repo_root().join("research").join("phase1-source-locks.json");
    let raw = fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));
    serde_json::from_str(&raw)
        .unwrap_or_else(|err| panic!("failed to parse {}: {err}", path.display()))
}

pub fn missing_markers(lock: &SourceLock) -> Vec<String> {
    let path = repo_root().join(&lock.path);
    let content = fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read lock target {}: {err}", path.display()));
    lock.must_contain
        .iter()
        .filter(|needle| !content.contains(needle.as_str()))
        .cloned()
        .collect()
}

