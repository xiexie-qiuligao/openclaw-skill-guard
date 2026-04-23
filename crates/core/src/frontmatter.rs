use std::collections::BTreeMap;

use crate::types::FrontmatterParseResult;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrontmatterDocument {
    pub frontmatter: FrontmatterParseResult,
    pub body: String,
}

pub fn parse_frontmatter(content: &str) -> FrontmatterDocument {
    let normalized = content.replace("\r\n", "\n").replace('\r', "\n");
    let mut lines = normalized.lines();

    if !matches!(lines.next(), Some("---")) {
        return FrontmatterDocument {
            frontmatter: FrontmatterParseResult {
                present: false,
                parsed: false,
                raw_block: None,
                fields: BTreeMap::new(),
                diagnostics: Vec::new(),
            },
            body: normalized,
        };
    }

    let mut raw_block_lines = Vec::new();
    let mut fields = BTreeMap::new();
    let mut diagnostics = Vec::new();
    let mut body_start = None;
    let all_lines: Vec<&str> = normalized.lines().collect();

    for (index, line) in all_lines.iter().enumerate().skip(1) {
        if *line == "---" {
            body_start = Some(index + 1);
            break;
        }
        raw_block_lines.push((*line).to_string());
        if line.trim().is_empty() {
            continue;
        }
        if let Some((key, value)) = line.split_once(':') {
            fields.insert(key.trim().to_string(), value.trim().to_string());
        } else {
            diagnostics.push(format!(
                "Malformed frontmatter line {}: {}",
                index + 1,
                line
            ));
        }
    }

    let body = if let Some(start) = body_start {
        all_lines[start..].join("\n")
    } else {
        diagnostics
            .push("Frontmatter opened with '---' but no closing delimiter was found.".to_string());
        normalized
    };

    FrontmatterDocument {
        frontmatter: FrontmatterParseResult {
            present: true,
            parsed: diagnostics.is_empty(),
            raw_block: Some(raw_block_lines.join("\n")),
            fields,
            diagnostics,
        },
        body,
    }
}

pub fn get_field<'a>(frontmatter: &'a FrontmatterParseResult, key: &str) -> Option<&'a str> {
    frontmatter.fields.get(key).map(|value| value.as_str())
}

pub fn parse_bool(value: Option<&str>, default: bool) -> bool {
    match value.map(|v| v.trim().to_ascii_lowercase()) {
        Some(ref value) if value == "true" => true,
        Some(ref value) if value == "false" => false,
        _ => default,
    }
}

#[cfg(test)]
mod tests {
    use super::parse_frontmatter;

    #[test]
    fn parses_basic_frontmatter() {
        let doc = parse_frontmatter("---\nname: Demo\ndescription: Test\n---\nBody");
        assert!(doc.frontmatter.present);
        assert_eq!(doc.frontmatter.fields["name"], "Demo");
        assert_eq!(doc.body, "Body");
    }

    #[test]
    fn malformed_frontmatter_produces_diagnostic() {
        let doc = parse_frontmatter("---\nname Demo\nbody: ok");
        assert!(doc.frontmatter.present);
        assert!(!doc.frontmatter.diagnostics.is_empty());
    }
}
