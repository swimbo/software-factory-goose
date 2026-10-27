//! Bounded source-side text assembly. Not yet wired to a mandatory tool boundary.
//!
//! Feed one complete logical text response into one buffer. No partial text is exposed:
//! only `finish(Complete)` can return masked output. Text errors and notifications may use
//! this primitive only after their entire text payload is assembled; structured content,
//! resources, and media must be rejected or separately normalized by a verified adapter.
//! A caller must never reuse this as a per-chunk mask or emit raw bytes after any error.

use crate::mask::{self, Masked};

pub const MAX_TOOL_TEXT_BYTES: usize = 1024 * 1024;

/// Input classification belongs to the trusted transport adapter, not model arguments.
pub enum InputChunk<'a> {
    /// Bytes may split a UTF-8 code point. Validation happens after complete assembly.
    Utf8Text(&'a [u8]),
    /// Any content without a supported complete-text normalization contract.
    Unsupported,
}

#[derive(Clone, Copy)]
/// The trusted producer must attest actual completion, never a model-generated flag.
pub enum Completion {
    Complete,
    Incomplete,
    Cancelled,
    Truncated,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputError {
    InvalidLimit,
    UnsupportedContent,
    LimitExceeded,
    Incomplete,
    InvalidUtf8,
}

impl std::fmt::Display for OutputError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::InvalidLimit => "invalid tool text limit",
            Self::UnsupportedContent => "unsupported tool content",
            Self::LimitExceeded => "tool text exceeds limit",
            Self::Incomplete => "tool text is incomplete",
            Self::InvalidUtf8 => "tool text is not valid UTF-8",
        })
    }
}

impl std::error::Error for OutputError {}

/// Intentionally has no Debug, Clone, raw-byte accessor, or partial-flush operation.
/// The cap bounds retained input and released output, not allocator or regex scratch space.
pub struct TextBuffer {
    limit: usize,
    bytes: Vec<u8>,
    failure: Option<OutputError>,
}

impl TextBuffer {
    pub fn new(limit: usize) -> Result<Self, OutputError> {
        if limit == 0 || limit > MAX_TOOL_TEXT_BYTES {
            return Err(OutputError::InvalidLimit);
        }
        Ok(Self {
            limit,
            bytes: Vec::new(),
            failure: None,
        })
    }

    pub fn push(&mut self, chunk: InputChunk<'_>) -> Result<(), OutputError> {
        if let Some(error) = self.failure {
            return Err(error);
        }
        let InputChunk::Utf8Text(bytes) = chunk else {
            return self.fail(OutputError::UnsupportedContent);
        };
        if bytes.len() > self.limit - self.bytes.len() {
            return self.fail(OutputError::LimitExceeded);
        }
        self.bytes.extend_from_slice(bytes);
        Ok(())
    }

    fn fail(&mut self, error: OutputError) -> Result<(), OutputError> {
        // Release the accumulated data; this is not a secure-erasure guarantee.
        self.bytes = Vec::new();
        self.failure = Some(error);
        Err(error)
    }

    /// Consumes the response so callers cannot resume or release it a second time.
    pub fn finish(self, completion: Completion) -> Result<Masked, OutputError> {
        if let Some(error) = self.failure {
            return Err(error);
        }
        if !matches!(completion, Completion::Complete) {
            return Err(OutputError::Incomplete);
        }
        let text = std::str::from_utf8(&self.bytes).map_err(|_| OutputError::InvalidUtf8)?;
        let masked = mask::mask(text);
        // Redaction labels can expand short matches. Do not release beyond the cap.
        if masked.text.len() > self.limit {
            return Err(OutputError::LimitExceeded);
        }
        Ok(masked)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn buffer(limit: usize) -> TextBuffer {
        TextBuffer::new(limit).unwrap()
    }

    #[test]
    fn every_secret_split_is_masked_after_complete_assembly() {
        let input = b"prefix sk-OFFLINE0123456789ABCDEFGHIJKLMN suffix";
        for split in 0..=input.len() {
            let mut b = buffer(256);
            b.push(InputChunk::Utf8Text(&input[..split])).unwrap();
            b.push(InputChunk::Utf8Text(&input[split..])).unwrap();
            let output = b.finish(Completion::Complete).unwrap();
            assert_eq!(output.text, "prefix [REDACTED] suffix", "split {split}");
            assert_eq!(output.redactions, vec!["api_key"]);
        }
    }

    #[test]
    fn split_utf8_and_empty_chunks_are_reassembled_without_loss() {
        let input = "ok: 🦀".as_bytes();
        let mut b = buffer(64);
        for byte in input {
            b.push(InputChunk::Utf8Text(&[])).unwrap();
            b.push(InputChunk::Utf8Text(std::slice::from_ref(byte)))
                .unwrap();
        }
        assert_eq!(b.finish(Completion::Complete).unwrap().text, "ok: 🦀");
    }

    #[test]
    fn invalid_or_unfinished_utf8_never_becomes_lossy_text() {
        for input in [&[0xff][..], &[0xe2, 0x82][..]] {
            let mut b = buffer(32);
            b.push(InputChunk::Utf8Text(input)).unwrap();
            assert_eq!(
                b.finish(Completion::Complete),
                Err(OutputError::InvalidUtf8)
            );
        }
    }

    #[test]
    fn incomplete_cancelled_and_truncated_never_release_partial_content() {
        for completion in [
            Completion::Incomplete,
            Completion::Cancelled,
            Completion::Truncated,
        ] {
            let mut b = buffer(32);
            b.push(InputChunk::Utf8Text(b"partial sk-OFF")).unwrap();
            assert_eq!(b.finish(completion), Err(OutputError::Incomplete));
        }
    }

    #[test]
    fn unsupported_content_poisons_preceding_and_subsequent_text() {
        let mut b = buffer(64);
        b.push(InputChunk::Utf8Text(b"initial text")).unwrap();
        assert_eq!(
            b.push(InputChunk::Unsupported),
            Err(OutputError::UnsupportedContent)
        );
        assert_eq!(
            b.push(InputChunk::Utf8Text(b"tail")),
            Err(OutputError::UnsupportedContent)
        );
        assert_eq!(
            b.finish(Completion::Complete),
            Err(OutputError::UnsupportedContent)
        );
    }

    #[test]
    fn exact_cap_succeeds_but_one_extra_byte_permanently_fails() {
        let mut exact = buffer(4);
        exact.push(InputChunk::Utf8Text(b"text")).unwrap();
        assert_eq!(exact.finish(Completion::Complete).unwrap().text, "text");
        let mut overflow = buffer(4);
        overflow.push(InputChunk::Utf8Text(b"text")).unwrap();
        assert_eq!(
            overflow.push(InputChunk::Utf8Text(b"!")),
            Err(OutputError::LimitExceeded)
        );
        assert_eq!(
            overflow.push(InputChunk::Utf8Text(b"")),
            Err(OutputError::LimitExceeded)
        );
        assert_eq!(
            overflow.finish(Completion::Complete),
            Err(OutputError::LimitExceeded)
        );
    }

    #[test]
    fn single_oversize_chunk_is_rejected_without_retaining_it() {
        let mut b = buffer(8);
        assert_eq!(
            b.push(InputChunk::Utf8Text(&[b'x'; 64])),
            Err(OutputError::LimitExceeded)
        );
        assert!(b.bytes.is_empty());
        assert_eq!(
            b.finish(Completion::Complete),
            Err(OutputError::LimitExceeded)
        );
    }

    #[test]
    fn redaction_expansion_cannot_exceed_release_limit() {
        let mut b = buffer(6);
        b.push(InputChunk::Utf8Text(b"a@b.co")).unwrap();
        assert_eq!(
            b.finish(Completion::Complete),
            Err(OutputError::LimitExceeded)
        );
    }

    #[test]
    fn invalid_limits_are_rejected() {
        assert!(matches!(TextBuffer::new(0), Err(OutputError::InvalidLimit)));
        assert!(matches!(
            TextBuffer::new(MAX_TOOL_TEXT_BYTES + 1),
            Err(OutputError::InvalidLimit)
        ));
        assert!(TextBuffer::new(MAX_TOOL_TEXT_BYTES).is_ok());
    }
}
