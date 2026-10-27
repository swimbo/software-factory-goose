use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Command, Stdio};

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("sfactory-tool-{}", ulid::Ulid::new()));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn request(&self, input: &str) -> serde_json::Value {
        let mut child = Command::new(env!("CARGO_BIN_EXE_execution"))
            .arg("--tool-request")
            .current_dir(&self.0)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(input.as_bytes())
            .unwrap();
        let result = child.wait_with_output().unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        serde_json::from_slice(&result.stdout).unwrap()
    }
    fn command(&self, command: &str) -> serde_json::Value {
        self.request(&serde_json::json!({"command": command}).to_string())
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn denied_command_never_executes_with_runnable_fixture_positive_control() {
    let f = Fixture::new();
    for name in ["allowed", "dd"] {
        let path = f.0.join(name);
        std::fs::write(&path, "#!/bin/sh\nprintf executed > marker\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    assert_eq!(f.command("./allowed")["status"], "executed");
    assert_eq!(
        std::fs::read_to_string(f.0.join("marker")).unwrap(),
        "executed"
    );
    std::fs::remove_file(f.0.join("marker")).unwrap();
    let denied = f.command("./dd");
    assert_eq!(denied["status"], "refused");
    assert_eq!(denied["reason"], "policy_denied");
    assert!(!f.0.join("marker").exists());
}

#[test]
fn split_secret_output_is_masked_and_nonzero_status_preserved() {
    let f = Fixture::new();
    let response = f.command("printf 'sk-OFF'; sleep 0.01; printf 'LINE0123456789ABCDEFGHIJKLMN'; printf 'password=fixture-only' >&2; exit 7");
    assert_eq!(response["status"], "executed");
    assert_eq!(response["exit_code"], 7);
    assert_eq!(response["stdout"], "[REDACTED]");
    assert_eq!(response["stderr"], "[REDACTED]");
    assert!(!response.to_string().contains("fixture-only"));
}

#[test]
fn caller_cannot_supply_policy_cwd_environment_or_timeout() {
    let f = Fixture::new();
    for field in ["cwd", "policy", "env", "timeout", "output_limit", "tool"] {
        let input = format!(r#"{{"command":"printf executed > marker","{field}":"override"}}"#);
        assert_eq!(f.request(&input)["reason"], "invalid_request");
        assert!(!f.0.join("marker").exists());
    }
    assert_eq!(f.request("not json")["reason"], "invalid_request");
}

#[test]
fn invalid_utf8_in_either_stream_withholds_both_streams() {
    let f = Fixture::new();
    let path = f.0.join("fixture-output");
    std::fs::write(&path, "#!/bin/sh\nprintf benign\nprintf '\\377' >&2\n").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
    let response = f.command("./fixture-output");
    assert_eq!(response["status"], "refused");
    assert_eq!(response["reason"], "output_withheld");
    assert!(response.get("stdout").is_none());
    assert!(response.get("stderr").is_none());
}
