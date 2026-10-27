//! Factory-owned shell request boundary; not an OS sandbox or mandatory Goose adapter.
//! Request bytes can select only command text. Trusted context owns execution authority.

use crate::{policy, supervise, tool_output};
use serde::{Deserialize, Serialize};
use std::io::Read;
use std::os::fd::{AsRawFd, BorrowedFd};
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

const MAX_REQUEST_BYTES: u64 = 64 * 1024;
const MAX_COMMAND_BYTES: usize = 16 * 1024;
const MAX_TIMEOUT: Duration = Duration::from_secs(180);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShellRequest {
    command: String,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum Response {
    /// The subprocess was observed and its complete text was masked. A nonzero exit
    /// remains nonzero; this is never a work-package completion or verification receipt.
    Executed {
        exit_code: i32,
        stdout: String,
        stderr: String,
    },
    Refused {
        reason: &'static str,
    },
}

impl Response {
    pub fn refused(reason: &'static str) -> Self {
        Self::Refused { reason }
    }
}

pub fn read_request(reader: impl Read) -> Result<ShellRequest, Response> {
    let mut bytes = Vec::new();
    reader
        .take(MAX_REQUEST_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| Response::refused("invalid_request"))?;
    if bytes.len() as u64 > MAX_REQUEST_BYTES {
        return Err(Response::refused("invalid_request"));
    }
    let request: ShellRequest =
        serde_json::from_slice(&bytes).map_err(|_| Response::refused("invalid_request"))?;
    if request.command.trim().is_empty()
        || request.command.len() > MAX_COMMAND_BYTES
        || request.command.as_bytes().contains(&0)
    {
        return Err(Response::refused("invalid_request"));
    }
    Ok(request)
}

/// One EOF-framed local request with a fixed deadline. Caller must own the only reader
/// of this descriptor. Does not alter descriptor flags or wait indefinitely for EOF.
pub fn read_local_request(input: BorrowedFd<'_>) -> Result<ShellRequest, Response> {
    read_with_deadline(input, REQUEST_TIMEOUT)
}

fn read_with_deadline(input: BorrowedFd<'_>, timeout: Duration) -> Result<ShellRequest, Response> {
    let start = Instant::now();
    let mut bytes = Vec::new();
    loop {
        let Some(remaining) = timeout.checked_sub(start.elapsed()) else {
            return Err(Response::refused("invalid_request"));
        };
        let mut descriptor = libc::pollfd {
            fd: input.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: borrowed descriptor remains alive; poll receives one valid pollfd.
        let ready = unsafe {
            libc::poll(
                &mut descriptor,
                1,
                remaining.as_millis().clamp(1, i32::MAX as u128) as i32,
            )
        };
        if ready < 0 && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
            continue;
        }
        if ready <= 0 || descriptor.revents & (libc::POLLIN | libc::POLLHUP) == 0 {
            return Err(Response::refused("invalid_request"));
        }
        let mut block = [0u8; 8192];
        // SAFETY: descriptor is live and block is writable for block.len() bytes. This
        // function is its sole reader, so poll readiness cannot be consumed elsewhere.
        let count =
            unsafe { libc::read(input.as_raw_fd(), block.as_mut_ptr().cast(), block.len()) };
        if count < 0 {
            if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(Response::refused("invalid_request"));
        }
        if count == 0 {
            return read_request(bytes.as_slice());
        }
        if bytes.len() + count as usize > MAX_REQUEST_BYTES as usize {
            return Err(Response::refused("invalid_request"));
        }
        bytes.extend_from_slice(&block[..count as usize]);
    }
}

pub struct ShellBoundary {
    cwd: PathBuf,
    rules: policy::RuleSet,
    timeout: Duration,
    output_limit: usize,
}

impl ShellBoundary {
    /// All arguments must be owned by the trusted launcher; none come from request JSON.
    pub fn new(
        cwd: &Path,
        rules: policy::RuleSet,
        timeout: Duration,
        output_limit: usize,
    ) -> Result<Self, Response> {
        let cwd = cwd
            .canonicalize()
            .map_err(|_| Response::refused("configuration_unavailable"))?;
        if !cwd.is_dir()
            || timeout.is_zero()
            || timeout > MAX_TIMEOUT
            || tool_output::TextBuffer::new(output_limit).is_err()
        {
            return Err(Response::refused("configuration_unavailable"));
        }
        Ok(Self {
            cwd,
            rules,
            timeout,
            output_limit,
        })
    }

    pub fn execute(&self, request: ShellRequest) -> Response {
        if !matches!(
            policy::evaluate_at(&self.rules, &request.command, &self.cwd),
            policy::Decision::Allow
        ) {
            return Response::refused("policy_denied");
        }
        let mut command = std::process::Command::new("/bin/sh");
        command
            .args(["-c", &request.command])
            .current_dir(&self.cwd)
            .env_clear()
            .env("PATH", "/usr/bin:/bin");
        let captured = match supervise(&mut command, self.timeout) {
            Ok(captured) => captured,
            Err(_) => return Response::refused("execution_unavailable"),
        };
        if captured.timed_out {
            return Response::refused("timed_out");
        }
        if captured.stdout.truncated
            || captured.stderr.truncated
            || !captured.stdout.eof
            || !captured.stderr.eof
        {
            return Response::refused("output_withheld");
        }
        // Assemble and validate both streams before releasing either. The supervisor's
        // private capture never becomes public output if either stream is rejected.
        let normalize = |bytes: &[u8]| -> Result<String, tool_output::OutputError> {
            let mut buffer = tool_output::TextBuffer::new(self.output_limit)?;
            for chunk in bytes.chunks(8192) {
                buffer.push(tool_output::InputChunk::Utf8Text(chunk))?;
            }
            Ok(buffer.finish(tool_output::Completion::Complete)?.text)
        };
        match (
            normalize(&captured.stdout.bytes),
            normalize(&captured.stderr.bytes),
        ) {
            (Ok(stdout), Ok(stderr)) => Response::Executed {
                exit_code: captured
                    .status
                    .code()
                    .unwrap_or(128 + captured.status.signal().unwrap_or(0)),
                stdout,
                stderr,
            },
            _ => Response::refused("output_withheld"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::os::fd::AsFd;

    #[test]
    fn request_bounds_and_invalid_shapes_fail_closed() {
        for input in [
            vec![b' '; MAX_REQUEST_BYTES as usize + 1],
            vec![0xff],
            br#"{"command":""}"#.to_vec(),
            br#"{"command":"x","command":"y"}"#.to_vec(),
        ] {
            assert!(read_request(input.as_slice()).is_err());
        }
        let oversized =
            serde_json::json!({"command": "x".repeat(MAX_COMMAND_BYTES + 1)}).to_string();
        assert!(read_request(oversized.as_bytes()).is_err());
    }

    #[test]
    fn partial_request_without_eof_cannot_hold_boundary_open() {
        let (reader, mut writer) = std::os::unix::net::UnixStream::pair().unwrap();
        writer
            .write_all(br#"{"command":"printf pending"}"#)
            .unwrap();
        let start = Instant::now();
        assert!(read_with_deadline(reader.as_fd(), Duration::from_millis(20)).is_err());
        assert!(start.elapsed() < Duration::from_secs(1));
        drop(writer);
        // Timed-out bytes are discarded; EOF cannot revive the old request.
        assert!(read_with_deadline(reader.as_fd(), Duration::from_millis(20)).is_err());
    }

    #[test]
    fn trusted_cwd_controls_policy_and_execution_without_global_chdir() {
        let temp = std::env::temp_dir().join(format!("sfactory-boundary-{}", ulid::Ulid::new()));
        std::fs::create_dir(&temp).unwrap();
        let initial = std::env::current_dir().unwrap();
        let rules = policy::RuleSet::default_rules(&temp.to_string_lossy());
        let boundary = ShellBoundary::new(&temp, rules, Duration::from_secs(2), 64).unwrap();
        let request =
            read_request(br#"{"command":"printf marker > relative-file"}"#.as_slice()).unwrap();
        assert!(matches!(
            boundary.execute(request),
            Response::Executed { exit_code: 0, .. }
        ));
        assert_eq!(
            std::fs::read_to_string(temp.join("relative-file")).unwrap(),
            "marker"
        );
        assert_eq!(std::env::current_dir().unwrap(), initial);
        std::fs::remove_dir_all(temp).unwrap();
    }

    #[test]
    fn timeout_and_limit_withhold_partial_successful_output() {
        let cwd = std::env::current_dir().unwrap();
        let rules = policy::RuleSet::default_rules(&cwd.to_string_lossy());
        let boundary = ShellBoundary::new(&cwd, rules.clone(), Duration::from_secs(2), 4).unwrap();
        let oversized = read_request(br#"{"command":"printf abcde"}"#.as_slice()).unwrap();
        assert_eq!(
            boundary.execute(oversized),
            Response::refused("output_withheld")
        );
        let boundary = ShellBoundary::new(&cwd, rules, Duration::from_millis(100), 4).unwrap();
        let slow = read_request(br#"{"command":"printf abc; sleep 1"}"#.as_slice()).unwrap();
        assert_eq!(boundary.execute(slow), Response::refused("timed_out"));
    }
}
