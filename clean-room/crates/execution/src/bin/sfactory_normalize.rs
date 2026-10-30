//! Complete-text normalization for the disabled harness candidate. No partial output.
#[path = "../mask.rs"]
mod mask;
#[allow(dead_code)] // This entry point accepts only complete text, not streaming/media.
#[path = "../tool_output.rs"]
mod tool_output;
use std::io::Read;

fn main() {
    let mut bytes = Vec::new();
    if std::io::stdin()
        .take(tool_output::MAX_TOOL_TEXT_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .is_err()
    {
        std::process::exit(1);
    }
    let result = (|| {
        let mut buffer = tool_output::TextBuffer::new(tool_output::MAX_TOOL_TEXT_BYTES)?;
        buffer.push(tool_output::InputChunk::Utf8Text(&bytes))?;
        buffer.finish(tool_output::Completion::Complete)
    })();
    match result {
        Ok(masked) => println!("{}", serde_json::json!({"text": masked.text})),
        Err(_) => std::process::exit(1),
    }
}
