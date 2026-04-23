use std::fs;
use std::path::{Path, PathBuf};

use thiserror::Error;
use walkdir::WalkDir;

use crate::types::{FileSkip, ScanIntegrityNote, ScanTarget, TargetKind};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileInventory {
    pub target: ScanTarget,
    pub files: Vec<PathBuf>,
    pub files_skipped: Vec<FileSkip>,
    pub scan_integrity_notes: Vec<ScanIntegrityNote>,
}

#[derive(Debug, Error)]
pub enum InventoryError {
    #[error("path does not exist: {0}")]
    MissingPath(String),
    #[error("failed to canonicalize {path}: {message}")]
    Canonicalize { path: String, message: String },
    #[error("failed to inspect {path}: {message}")]
    Inspect { path: String, message: String },
}

pub fn build_inventory(path: &Path) -> Result<FileInventory, InventoryError> {
    if !path.exists() {
        return Err(InventoryError::MissingPath(path.display().to_string()));
    }

    let canonical = path
        .canonicalize()
        .map_err(|err| InventoryError::Canonicalize {
            path: path.display().to_string(),
            message: err.to_string(),
        })?;
    let metadata = fs::metadata(&canonical).map_err(|err| InventoryError::Inspect {
        path: canonical.display().to_string(),
        message: err.to_string(),
    })?;

    let target_kind = classify_target_kind(&canonical, metadata.is_file());
    let target = ScanTarget {
        path: path.display().to_string(),
        canonical_path: canonical.display().to_string(),
        target_kind,
    };

    if metadata.is_file() {
        return Ok(FileInventory {
            target,
            files: vec![canonical],
            files_skipped: Vec::new(),
            scan_integrity_notes: Vec::new(),
        });
    }

    let mut files = Vec::new();
    let mut files_skipped = Vec::new();
    let mut scan_integrity_notes = Vec::new();

    for entry in WalkDir::new(&canonical).follow_links(false) {
        match entry {
            Ok(entry) => {
                if entry.file_type().is_file() {
                    files.push(entry.path().to_path_buf());
                }
            }
            Err(err) => {
                let display_path = err
                    .path()
                    .map(|path| path.display().to_string())
                    .unwrap_or_else(|| canonical.display().to_string());
                files_skipped.push(FileSkip {
                    path: display_path.clone(),
                    reason: format!("walk error: {err}"),
                });
                scan_integrity_notes.push(ScanIntegrityNote {
                    kind: "partial_scan".to_string(),
                    message: err.to_string(),
                    path: Some(display_path),
                });
            }
        }
    }

    files.sort();

    Ok(FileInventory {
        target,
        files,
        files_skipped,
        scan_integrity_notes,
    })
}

fn classify_target_kind(path: &Path, is_file: bool) -> TargetKind {
    if is_file {
        return TargetKind::File;
    }

    if path.join("SKILL.md").is_file() {
        return TargetKind::SkillDir;
    }

    TargetKind::SkillsRoot
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::tempdir;

    use super::build_inventory;
    use crate::types::TargetKind;

    #[test]
    fn inventory_recurses_nested_directories() {
        let dir = tempdir().unwrap();
        let nested = dir.path().join("nested").join("deeper");
        fs::create_dir_all(&nested).unwrap();
        fs::write(dir.path().join("SKILL.md"), "# skill").unwrap();
        fs::write(nested.join("helper.sh"), "echo hi").unwrap();

        let inventory = build_inventory(dir.path()).unwrap();

        assert_eq!(inventory.target.target_kind, TargetKind::SkillDir);
        assert_eq!(inventory.files.len(), 2);
    }
}
