//! Output masking (R14) — scrub secrets from tool output before it enters the model context.
//!
//! R10 stops secrets being *injected* into the worker; this stops them *leaking out* through a
//! tool result. Patterns are ordered most-specific-first (PEM, provider keys) before generic
//! shapes (IPs, emails). Deterministic — no LLM.

use regex::{Regex, RegexSet};
use std::sync::LazyLock;

/// Redaction kinds, in the same order as `PATTERNS`.
const KINDS: [&str; 7] = [
    "api_key",
    "aws_key",
    "pem",
    "home_path",
    "ipv4",
    "email",
    "credential_assignment",
];

const PATTERNS: [&str; 7] = [
    // provider key shapes: OpenAI/Anthropic (sk-), GitHub (ghp_), GitLab (glpat-)
    r"(?:sk-[A-Za-z0-9_\-]{16,}|ghp_[A-Za-z0-9]{20,}|glpat-[A-Za-z0-9_\-]{16,})",
    // AWS access-key id
    r"AKIA[0-9A-Z]{16}",
    // PEM private-key block (multiline, non-greedy)
    r"(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----",
    // macOS home path (the username segment is the sensitive part)
    r"/Users/[A-Za-z0-9._\-]+",
    // IPv4 (valid octets, to limit false positives on version strings)
    r"\b(?:(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\b",
    // email
    r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b",
    // Common credential labels and authorization headers. This is heuristic, not DLP.
    r#"(?i)(?:[a-z0-9_]*(?:token|password|secret|api_key)[a-z0-9_]*\s*[:=]\s*["']?[^\s"']+|authorization\s*:\s*(?:bearer|basic)\s+[^\s]+)"#,
];

static COMPILED: LazyLock<(RegexSet, Vec<Regex>)> = LazyLock::new(|| {
    let set = RegexSet::new(PATTERNS).expect("mask patterns compile");
    let individual: Vec<Regex> = PATTERNS
        .iter()
        .map(|p| Regex::new(p).expect("pattern compiles"))
        .collect();
    (set, individual)
});

/// The result of masking: the scrubbed text and which kinds were redacted.
#[derive(Debug, PartialEq)]
pub struct Masked {
    pub text: String,
    pub redactions: Vec<&'static str>,
}

/// Mask secrets in `input`. Returns the scrubbed text plus the redacted kinds — for an audit
/// event that records *that* a redaction happened, never the secret itself.
pub fn mask(input: &str) -> Masked {
    let (set, individual) = &*COMPILED;
    let matched: Vec<usize> = set.matches(input).iter().collect();
    if matched.is_empty() {
        return Masked {
            text: input.to_string(),
            redactions: Vec::new(),
        };
    }
    let mut text = input.to_string();
    let mut redactions = Vec::new();
    for idx in matched {
        if individual[idx].is_match(&text) {
            text = individual[idx]
                .replace_all(&text, "[REDACTED]")
                .into_owned();
            redactions.push(KINDS[idx]);
        }
    }
    Masked { text, redactions }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn masks_provider_keys() {
        let m = mask("token=sk-abcdefghijklmnop1234567890 done");
        assert!(!m.text.contains("sk-abcdefghijklmnop"));
        assert!(m.text.contains("[REDACTED]"));
        assert!(m.redactions.contains(&"api_key"));
    }

    #[test]
    fn masks_pem_block() {
        let pem = "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----";
        let m = mask(pem);
        assert_eq!(m.text, "[REDACTED]");
        assert!(m.redactions.contains(&"pem"));
    }

    #[test]
    fn masks_aws_key_and_home_path() {
        let m = mask("AKIAIOSFODNN7EXAMPLE at /Users/bo/secret.txt");
        assert!(!m.text.contains("AKIAIOSFODNN7EXAMPLE"));
        assert!(!m.text.contains("/Users/bo"));
        assert!(m.redactions.contains(&"aws_key"));
        assert!(m.redactions.contains(&"home_path"));
    }

    #[test]
    fn masks_email_and_ipv4() {
        let m = mask("contact me@example.com via 192.168.1.10");
        assert!(!m.text.contains("me@example.com"));
        assert!(!m.text.contains("192.168.1.10"));
        assert!(m.redactions.contains(&"email"));
        assert!(m.redactions.contains(&"ipv4"));
    }

    #[test]
    fn leaves_benign_output_unchanged() {
        let benign = "Compiling control-plane v0.1.0\nFinished dev profile in 2.4s";
        let m = mask(benign);
        assert_eq!(m.text, benign);
        assert!(m.redactions.is_empty());
    }
}
