use std::process::Command;

fn execution() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_execution"));
    command.env_clear().env("PATH", "/usr/bin:/bin");
    command
}

#[test]
fn shim_masks_stdout_and_stderr_before_returning_them() {
    let output = execution()
        .args([
            "--run-shell",
            "printf 'sk-abcdefghijklmnop1234567890'; printf 'password=hunter123' >&2",
        ])
        .output()
        .unwrap();
    assert!(output.status.success());
    assert_eq!(String::from_utf8(output.stdout).unwrap(), "[REDACTED]");
    assert_eq!(String::from_utf8(output.stderr).unwrap(), "[REDACTED]");
}

#[test]
fn shim_preserves_nonzero_exit_and_never_executes_denied_command() {
    let result = execution()
        .args(["--run-shell", "exit 7"])
        .output()
        .unwrap();
    assert_eq!(result.status.code(), Some(7));
    let result = execution()
        .args(["--run-shell", "dd if=/dev/zero"])
        .output()
        .unwrap();
    assert_eq!(result.status.code(), Some(126));
    assert!(result.stdout.is_empty());
}

#[test]
fn explicitly_missing_policy_is_not_silently_replaced_by_defaults() {
    let output = execution()
        .env("SFACTORY_POLICY", "/nonexistent/sfactory-policy.toml")
        .args(["--run-shell", "printf executed"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
}

#[test]
fn inherited_secret_is_not_available_to_shell_child() {
    let output = execution()
        .env("SFACTORY_TEST_AMBIENT_SECRET", "sensitive-fixture")
        .args(["--run-shell", "printenv"])
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(
        !String::from_utf8(output.stdout)
            .unwrap()
            .contains("sensitive-fixture")
    );
}
