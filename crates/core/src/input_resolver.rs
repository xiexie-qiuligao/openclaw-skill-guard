use std::fs;
use std::io::{Cursor, Read};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use tempfile::TempDir;
use thiserror::Error;
use zip::ZipArchive;

use crate::policy::PolicyConfig;
use crate::types::{InputOrigin, InputOriginKind};

const REMOTE_SKILL_DISPLAY: &str = "<remote-skill>/SKILL.md";
const REMOTE_ARCHIVE_DISPLAY: &str = "<remote-archive>";

#[derive(Debug, Clone)]
pub struct ScanTargetOptions {
    pub suppression_path: Option<PathBuf>,
    pub runtime_manifest_path: Option<PathBuf>,
    pub validation_mode: crate::types::ValidationExecutionMode,
    pub policy_path: Option<PathBuf>,
    pub ci_mode: bool,
    pub no_network: bool,
    pub remote_cache_dir: Option<PathBuf>,
    pub agent_ecosystem: bool,
}

#[derive(Debug)]
pub struct ResolvedTarget {
    pub path: PathBuf,
    pub origin: InputOrigin,
    _tempdir: Option<TempDir>,
}

#[derive(Debug, Error)]
pub enum InputResolveError {
    #[error("{0}")]
    Message(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Zip(#[from] zip::result::ZipError),
}

pub fn resolve_scan_target(
    input: &str,
    policy: &PolicyConfig,
    no_network: bool,
    remote_cache_dir: Option<&Path>,
) -> Result<ResolvedTarget, InputResolveError> {
    if !is_url(input) {
        let path = PathBuf::from(input);
        return Ok(ResolvedTarget {
            origin: InputOrigin {
                original_input: input.to_string(),
                resolved_kind: InputOriginKind::LocalPath,
                source_host: None,
                resolved_path: path.display().to_string(),
                reference: None,
                warnings: Vec::new(),
            },
            path,
            _tempdir: None,
        });
    }

    if no_network || policy.remote_input.eq_ignore_ascii_case("deny") {
        return Err(InputResolveError::Message(
            "当前配置禁止远程 skill 链接输入。".to_string(),
        ));
    }
    if !input.starts_with("https://") {
        return Err(InputResolveError::Message(
            "远程 skill 链接必须使用 HTTPS。".to_string(),
        ));
    }

    let max_bytes = policy.max_remote_bytes.unwrap_or(50 * 1024 * 1024);
    let max_files = policy.max_archive_files.unwrap_or(2000);
    let (workdir, tempdir) = prepare_workdir(remote_cache_dir)?;
    let host = host_from_url(input);
    let parsed = parse_remote_input(input);

    match parsed {
        RemoteInput::SingleFile {
            url,
            kind,
            reference,
        } => {
            let bytes = download_limited(&url, max_bytes)?;
            reject_probably_non_text(&bytes)?;
            let target = workdir.join("SKILL.md");
            fs::write(&target, bytes)?;
            Ok(ResolvedTarget {
                path: target,
                origin: InputOrigin {
                    original_input: input.to_string(),
                    resolved_kind: kind,
                    source_host: host,
                    resolved_path: REMOTE_SKILL_DISPLAY.to_string(),
                    reference,
                    warnings: Vec::new(),
                },
                _tempdir: tempdir,
            })
        }
        RemoteInput::ZipArchive {
            urls,
            kind,
            reference,
            subpath,
        } => {
            let mut last_error = None;
            for url in urls {
                match download_limited(&url, max_bytes).and_then(|bytes| {
                    extract_zip_limited(&bytes, &workdir, max_files, max_bytes)?;
                    Ok(())
                }) {
                    Ok(()) => {
                        let scan_root = choose_extracted_root(&workdir, subpath.as_deref())?;
                        let display_path = subpath
                            .as_deref()
                            .map(|value| format!("{REMOTE_ARCHIVE_DISPLAY}/{value}"))
                            .unwrap_or_else(|| REMOTE_ARCHIVE_DISPLAY.to_string());
                        return Ok(ResolvedTarget {
                            path: scan_root,
                            origin: InputOrigin {
                                original_input: input.to_string(),
                                resolved_kind: kind,
                                source_host: host,
                                resolved_path: display_path,
                                reference,
                                warnings: Vec::new(),
                            },
                            _tempdir: tempdir,
                        });
                    }
                    Err(err) => last_error = Some(err),
                }
            }
            Err(last_error
                .unwrap_or_else(|| InputResolveError::Message("远程归档下载失败。".to_string())))
        }
    }
}

enum RemoteInput {
    SingleFile {
        url: String,
        kind: InputOriginKind,
        reference: Option<String>,
    },
    ZipArchive {
        urls: Vec<String>,
        kind: InputOriginKind,
        reference: Option<String>,
        subpath: Option<String>,
    },
}

fn parse_remote_input(input: &str) -> RemoteInput {
    if input.contains("raw.githubusercontent.com/") {
        return RemoteInput::SingleFile {
            url: input.to_string(),
            kind: InputOriginKind::RawSkill,
            reference: None,
        };
    }
    if input.ends_with(".zip") {
        return RemoteInput::ZipArchive {
            urls: vec![input.to_string()],
            kind: InputOriginKind::ZipArchive,
            reference: None,
            subpath: None,
        };
    }
    if let Some(parts) = github_parts(input) {
        if let Some(index) = parts.iter().position(|part| *part == "blob") {
            if parts.len() > index + 2 {
                let owner = parts[0];
                let repo = parts[1];
                let reference = parts[index + 1];
                let path = parts[index + 2..].join("/");
                return RemoteInput::SingleFile {
                    url: format!(
                        "https://raw.githubusercontent.com/{owner}/{repo}/{reference}/{path}"
                    ),
                    kind: InputOriginKind::GithubBlob,
                    reference: Some(reference.to_string()),
                };
            }
        }
        if let Some(index) = parts.iter().position(|part| *part == "tree") {
            if parts.len() > index + 1 {
                let owner = parts[0];
                let repo = parts[1];
                let reference = parts[index + 1];
                let subpath = if parts.len() > index + 2 {
                    Some(parts[index + 2..].join("/"))
                } else {
                    None
                };
                return RemoteInput::ZipArchive {
                    urls: vec![github_archive(owner, repo, reference)],
                    kind: InputOriginKind::GithubTree,
                    reference: Some(reference.to_string()),
                    subpath,
                };
            }
        }
        if parts.len() >= 2 {
            return RemoteInput::ZipArchive {
                urls: vec![
                    github_archive(parts[0], parts[1], "main"),
                    github_archive(parts[0], parts[1], "master"),
                ],
                kind: InputOriginKind::GithubRepo,
                reference: None,
                subpath: None,
            };
        }
    }
    if input.ends_with("/SKILL.md") {
        return RemoteInput::SingleFile {
            url: input.to_string(),
            kind: InputOriginKind::RawSkill,
            reference: None,
        };
    }
    RemoteInput::SingleFile {
        url: input.to_string(),
        kind: InputOriginKind::HttpsSkill,
        reference: None,
    }
}

fn is_url(input: &str) -> bool {
    input.starts_with("http://") || input.starts_with("https://")
}

fn host_from_url(input: &str) -> Option<String> {
    input
        .split_once("://")
        .and_then(|(_, rest)| rest.split('/').next())
        .map(str::to_string)
}

fn github_parts(input: &str) -> Option<Vec<&str>> {
    let rest = input.strip_prefix("https://github.com/")?;
    let parts = rest
        .trim_matches('/')
        .split('/')
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>();
    if parts.len() >= 2 {
        Some(parts)
    } else {
        None
    }
}

fn github_archive(owner: &str, repo: &str, reference: &str) -> String {
    format!("https://codeload.github.com/{owner}/{repo}/zip/refs/heads/{reference}")
}

fn prepare_workdir(
    remote_cache_dir: Option<&Path>,
) -> Result<(PathBuf, Option<TempDir>), InputResolveError> {
    if let Some(base) = remote_cache_dir {
        fs::create_dir_all(base)?;
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_millis())
            .unwrap_or(0);
        let path = base.join(format!("openclaw-skill-{suffix}"));
        fs::create_dir_all(&path)?;
        Ok((path, None))
    } else {
        let tempdir = tempfile::Builder::new()
            .prefix("openclaw-skill-")
            .tempdir()
            .map_err(InputResolveError::Io)?;
        Ok((tempdir.path().to_path_buf(), Some(tempdir)))
    }
}

fn download_limited(url: &str, max_bytes: u64) -> Result<Vec<u8>, InputResolveError> {
    let response = ureq::get(url)
        .call()
        .map_err(|err| InputResolveError::Message(format!("下载远程 skill 失败：{err}")))?;
    let mut reader = response.into_reader().take(max_bytes + 1);
    let mut bytes = Vec::new();
    reader.read_to_end(&mut bytes)?;
    if bytes.len() as u64 > max_bytes {
        return Err(InputResolveError::Message(format!(
            "远程内容超过大小限制（{max_bytes} 字节）。"
        )));
    }
    Ok(bytes)
}

fn reject_probably_non_text(bytes: &[u8]) -> Result<(), InputResolveError> {
    if bytes.iter().take(4096).any(|byte| *byte == 0) {
        return Err(InputResolveError::Message(
            "远程 skill 内容看起来不是文本文件，已拒绝扫描。".to_string(),
        ));
    }
    Ok(())
}

fn extract_zip_limited(
    bytes: &[u8],
    target: &Path,
    max_files: usize,
    max_uncompressed_bytes: u64,
) -> Result<(), InputResolveError> {
    let cursor = Cursor::new(bytes);
    let mut archive = ZipArchive::new(cursor)?;
    if archive.len() > max_files {
        return Err(InputResolveError::Message(format!(
            "远程归档文件数量超过限制（{max_files}）。"
        )));
    }

    let mut total_uncompressed = 0_u64;
    let mut regular_files = 0_usize;
    let mut non_text_files = 0_usize;

    for index in 0..archive.len() {
        let mut file = archive.by_index(index)?;
        let Some(relative) = file.enclosed_name().map(|path| path.to_path_buf()) else {
            return Err(InputResolveError::Message(
                "远程归档包含不安全路径，已拒绝扫描。".to_string(),
            ));
        };

        if file.is_dir() {
            fs::create_dir_all(target.join(relative))?;
            continue;
        }

        regular_files += 1;
        let size = file.size();
        if size > max_uncompressed_bytes {
            return Err(InputResolveError::Message(format!(
                "远程归档中存在超过大小限制的单个文件（{max_uncompressed_bytes} 字节）。"
            )));
        }
        total_uncompressed = total_uncompressed.saturating_add(size);
        if total_uncompressed > max_uncompressed_bytes {
            return Err(InputResolveError::Message(format!(
                "远程归档解压后内容超过大小限制（{max_uncompressed_bytes} 字节）。"
            )));
        }

        let out_path = target.join(relative);
        if let Some(parent) = out_path.parent() {
            fs::create_dir_all(parent)?;
        }
        let mut bytes = Vec::with_capacity(size.min(1024 * 1024) as usize);
        file.read_to_end(&mut bytes)?;
        if !looks_like_text_file(&out_path, &bytes) {
            non_text_files += 1;
        }
        fs::write(&out_path, bytes)?;
    }

    if regular_files > 0 && non_text_files * 100 / regular_files > 60 {
        return Err(InputResolveError::Message(
            "远程归档中文本文件比例过低，已拒绝扫描。".to_string(),
        ));
    }

    Ok(())
}

fn looks_like_text_file(path: &Path, bytes: &[u8]) -> bool {
    let text_extension = path
        .extension()
        .and_then(|value| value.to_str())
        .map(|value| {
            matches!(
                value.to_ascii_lowercase().as_str(),
                "md" | "txt"
                    | "json"
                    | "yaml"
                    | "yml"
                    | "toml"
                    | "lock"
                    | "py"
                    | "js"
                    | "ts"
                    | "rs"
                    | "sh"
                    | "ps1"
            )
        })
        .unwrap_or(false);
    text_extension || !bytes.iter().take(4096).any(|byte| *byte == 0)
}

fn choose_extracted_root(
    workdir: &Path,
    subpath: Option<&str>,
) -> Result<PathBuf, InputResolveError> {
    let mut dirs = fs::read_dir(workdir)?
        .filter_map(Result::ok)
        .filter(|entry| entry.path().is_dir())
        .map(|entry| entry.path())
        .collect::<Vec<_>>();
    dirs.sort();
    let root = dirs
        .first()
        .cloned()
        .unwrap_or_else(|| workdir.to_path_buf());
    if let Some(subpath) = subpath {
        let candidate = root.join(subpath);
        if candidate.exists() {
            return Ok(candidate);
        }
    }
    Ok(root)
}

#[cfg(test)]
mod tests {
    use std::io::{Cursor, Write};

    use tempfile::tempdir;
    use zip::write::FileOptions;

    use super::{
        extract_zip_limited, parse_remote_input, resolve_scan_target, InputResolveError,
        RemoteInput,
    };
    use crate::policy::PolicyConfig;
    use crate::types::InputOriginKind;

    #[test]
    fn local_path_keeps_legacy_scan_target_behavior() {
        let resolved = resolve_scan_target(
            "fixtures/v1/benign/SKILL.md",
            &PolicyConfig::default(),
            false,
            None,
        )
        .unwrap();

        assert_eq!(resolved.origin.resolved_kind, InputOriginKind::LocalPath);
        assert_eq!(
            resolved.path.to_string_lossy(),
            "fixtures/v1/benign/SKILL.md"
        );
    }

    #[test]
    fn no_network_blocks_remote_skill_links_with_clear_error() {
        let err = resolve_scan_target(
            "https://example.invalid/SKILL.md",
            &PolicyConfig::default(),
            true,
            None,
        )
        .unwrap_err();

        match err {
            InputResolveError::Message(message) => {
                assert!(message.contains("禁止") || message.contains("远程"));
            }
            other => panic!("unexpected resolver error: {other:?}"),
        }
    }

    #[test]
    fn http_remote_links_are_rejected_before_download() {
        let err = resolve_scan_target(
            "http://example.invalid/SKILL.md",
            &PolicyConfig::default(),
            false,
            None,
        )
        .unwrap_err();

        match err {
            InputResolveError::Message(message) => assert!(message.contains("HTTPS")),
            other => panic!("unexpected resolver error: {other:?}"),
        }
    }

    #[test]
    fn zip_limits_reject_too_many_files() {
        let mut buffer = Cursor::new(Vec::new());
        {
            let mut archive = zip::ZipWriter::new(&mut buffer);
            archive
                .start_file::<_, ()>("root/SKILL.md", FileOptions::default())
                .unwrap();
            archive.write_all(b"# Demo").unwrap();
            archive
                .start_file::<_, ()>("root/README.md", FileOptions::default())
                .unwrap();
            archive.write_all(b"# Readme").unwrap();
            archive.finish().unwrap();
        }

        let dir = tempdir().unwrap();
        let err = extract_zip_limited(&buffer.into_inner(), dir.path(), 1, 1024).unwrap_err();
        match err {
            InputResolveError::Message(message) => assert!(message.contains("数量")),
            other => panic!("unexpected resolver error: {other:?}"),
        }
    }

    #[test]
    fn github_blob_url_is_converted_to_raw_skill_download() {
        let parsed = parse_remote_input("https://github.com/acme/demo/blob/main/SKILL.md");

        match parsed {
            RemoteInput::SingleFile {
                url,
                kind,
                reference,
            } => {
                assert_eq!(kind, InputOriginKind::GithubBlob);
                assert_eq!(reference.as_deref(), Some("main"));
                assert_eq!(
                    url,
                    "https://raw.githubusercontent.com/acme/demo/main/SKILL.md"
                );
            }
            RemoteInput::ZipArchive { .. } => panic!("blob URL must not be treated as a zip"),
        }
    }

    #[test]
    fn zip_path_traversal_is_rejected() {
        let mut buffer = Cursor::new(Vec::new());
        {
            let mut archive = zip::ZipWriter::new(&mut buffer);
            archive
                .start_file::<_, ()>("../SKILL.md", FileOptions::default())
                .unwrap();
            archive.write_all(b"# Demo").unwrap();
            archive.finish().unwrap();
        }

        let dir = tempdir().unwrap();
        let err = extract_zip_limited(&buffer.into_inner(), dir.path(), 10, 1024).unwrap_err();
        match err {
            InputResolveError::Message(message) => assert!(message.contains("不安全路径")),
            other => panic!("unexpected resolver error: {other:?}"),
        }
    }
}
