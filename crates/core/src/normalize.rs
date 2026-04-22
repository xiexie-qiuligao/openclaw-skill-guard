use std::fs;
use std::path::Path;

use crate::types::ParseError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TextDocument {
    pub content: String,
    pub encoding: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormalizedLine {
    pub start_line: usize,
    pub text: String,
}

pub fn read_text_document(path: &Path) -> Result<TextDocument, ParseError> {
    let bytes = fs::read(path).map_err(|err| ParseError {
        path: path.display().to_string(),
        message: err.to_string(),
    })?;

    if bytes.is_empty() {
        return Ok(TextDocument {
            content: String::new(),
            encoding: "utf-8",
        });
    }

    if let Ok(content) = String::from_utf8(bytes.clone()) {
        return Ok(TextDocument {
            content,
            encoding: "utf-8",
        });
    }

    if let Some(content) = decode_utf16(&bytes) {
        return Ok(TextDocument {
            content,
            encoding: "utf-16",
        });
    }

    Err(ParseError {
        path: path.display().to_string(),
        message: "unsupported or binary file".to_string(),
    })
}

pub fn normalize_text(content: &str) -> String {
    content.replace("\r\n", "\n").replace('\r', "\n")
}

pub fn build_scan_lines(content: &str) -> Vec<NormalizedLine> {
    let content = normalize_text(content);
    let raw_lines: Vec<&str> = content.lines().collect();
    let mut output = Vec::new();
    let mut index = 0;

    while index < raw_lines.len() {
        let start_line = index + 1;
        let mut combined = raw_lines[index].trim_end().to_string();

        while index + 1 < raw_lines.len() && should_continue(&combined) {
            combined = strip_continuation_marker(&combined);
            let next = raw_lines[index + 1].trim_start();
            if !combined.is_empty() && !combined.ends_with(' ') {
                combined.push(' ');
            }
            combined.push_str(next);
            index += 1;
        }

        output.push(NormalizedLine {
            start_line,
            text: combined,
        });
        index += 1;
    }

    if output.is_empty() {
        output.push(NormalizedLine {
            start_line: 1,
            text: String::new(),
        });
    }

    output
}

fn should_continue(line: &str) -> bool {
    let trimmed = line.trim_end();
    trimmed.ends_with('\\') || trimmed.ends_with('`') || trimmed.ends_with('+')
}

fn strip_continuation_marker(line: &str) -> String {
    line.trim_end()
        .trim_end_matches('\\')
        .trim_end_matches('`')
        .trim_end_matches('+')
        .trim_end()
        .to_string()
}

fn decode_utf16(bytes: &[u8]) -> Option<String> {
    if bytes.len() < 2 {
        return None;
    }

    if bytes.starts_with(&[0xFF, 0xFE]) {
        return String::from_utf16(
            &bytes[2..]
                .chunks_exact(2)
                .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
                .collect::<Vec<_>>(),
        )
        .ok();
    }

    if bytes.starts_with(&[0xFE, 0xFF]) {
        return String::from_utf16(
            &bytes[2..]
                .chunks_exact(2)
                .map(|chunk| u16::from_be_bytes([chunk[0], chunk[1]]))
                .collect::<Vec<_>>(),
        )
        .ok();
    }

    let even_zeroes = bytes.iter().step_by(2).filter(|&&byte| byte == 0).count();
    let odd_zeroes = bytes.iter().skip(1).step_by(2).filter(|&&byte| byte == 0).count();

    if odd_zeroes > bytes.len() / 4 {
        return String::from_utf16(
            &bytes
                .chunks_exact(2)
                .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
                .collect::<Vec<_>>(),
        )
        .ok();
    }

    if even_zeroes > bytes.len() / 4 {
        return String::from_utf16(
            &bytes
                .chunks_exact(2)
                .map(|chunk| u16::from_be_bytes([chunk[0], chunk[1]]))
                .collect::<Vec<_>>(),
        )
        .ok();
    }

    None
}

#[cfg(test)]
mod tests {
    use super::{build_scan_lines, normalize_text};

    #[test]
    fn normalization_rewrites_line_endings() {
        assert_eq!(normalize_text("a\r\nb\rc"), "a\nb\nc");
    }

    #[test]
    fn scan_lines_join_backslash_and_plus_continuations() {
        let lines = build_scan_lines("curl https://x \\\n| bash\nconst cmd = 'a' +\n'b';");

        assert_eq!(lines[0].start_line, 1);
        assert!(lines[0].text.contains("| bash"));
        assert_eq!(lines[1].start_line, 3);
        assert_eq!(lines[1].text, "const cmd = 'a' 'b';");
    }
}

