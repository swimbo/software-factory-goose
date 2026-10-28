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

#[test]
fn termination_signals_withhold_output_and_stop_in_group_descendants() {
    // The unsignalled run proves the ready/release handshake really reaches the
    // descendant. Signal runs release only after the execution parent has exited.
    for signal in [None, Some(libc::SIGTERM), Some(libc::SIGINT)] {
        let f = Fixture::new();
        let script = f.0.join("long-tool");
        std::fs::write(&script, "#!/bin/sh\nprintf partial-output\n(printf ready > descendant.ready; n=0; while [ ! -e release ] && [ \"$n\" -lt 500 ]; do sleep 0.02; n=$((n+1)); done; if [ -e release ]; then printf survived > late.marker; fi) >/dev/null 2>&1 &\nwait\n").unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o700)).unwrap();
        let mut child = Command::new(env!("CARGO_BIN_EXE_execution"))
            .arg("--tool-request")
            .current_dir(&f.0)
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
            .write_all(br#"{"command":"./long-tool"}"#)
            .unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
        while !f.0.join("descendant.ready").exists() && std::time::Instant::now() < deadline {
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        assert!(
            f.0.join("descendant.ready").exists(),
            "descendant never became ready"
        );
        assert!(
            child.try_wait().unwrap().is_none(),
            "execution exited before test action"
        );
        assert!(
            !f.0.join("late.marker").exists(),
            "marker appeared before release"
        );
        if let Some(signal) = signal {
            // SAFETY: this test owns the running child and sends only the selected signal.
            assert_eq!(unsafe { libc::kill(child.id() as i32, signal) }, 0);
        } else {
            std::fs::write(f.0.join("release"), b"go").unwrap();
        }
        let output = child.wait_with_output().unwrap();
        if let Some(signal) = signal {
            std::fs::write(f.0.join("release"), b"go").unwrap();
            std::thread::sleep(std::time::Duration::from_secs(2));
            assert!(
                !f.0.join("late.marker").exists(),
                "descendant survived signal {signal}"
            );
        } else {
            assert!(
                f.0.join("late.marker").exists(),
                "positive descendant did not run"
            );
            continue;
        }
        let response: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(response["status"], "refused");
        assert_eq!(response["reason"], "execution_unavailable");
        assert!(response.get("stdout").is_none());
    }
}

#[test]
fn inherited_auto_reaping_refuses_before_shell_spawn() {
    use std::os::unix::process::CommandExt;
    let f = Fixture::new();
    let mut command = Command::new(env!("CARGO_BIN_EXE_execution"));
    command
        .arg("--tool-request")
        .current_dir(&f.0)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // SAFETY: pre_exec invokes only the async-signal-safe signal syscall in this child.
    unsafe {
        command.pre_exec(|| {
            libc::signal(libc::SIGCHLD, libc::SIG_IGN);
            Ok(())
        });
    }
    let mut child = command.spawn().unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(br#"{"command":"printf executed > marker"}"#)
        .unwrap();
    let output = child.wait_with_output().unwrap();
    let response: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(response["reason"], "execution_unavailable");
    assert!(!f.0.join("marker").exists());
}

#[cfg(feature = "fixture-inherited-group")]
#[test]
fn inherited_group_fixture_refuses_without_direct_leader_parent() {
    use std::os::unix::process::CommandExt;
    let f = Fixture::new();
    let mut child = Command::new(env!("CARGO_BIN_EXE_execution"))
        .arg("--fixture-inherited-tool-request")
        .current_dir(&f.0)
        .env_clear()
        .process_group(0)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    // It may reject before reading the pipe; a broken pipe is an allowed outcome.
    let _ = child
        .stdin
        .take()
        .unwrap()
        .write_all(br#"{"command":"printf bad > marker"}"#);
    assert!(!child.wait().unwrap().success());
    assert!(!f.0.join("marker").exists());
}
