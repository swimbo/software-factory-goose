use super::*;

fn fixture(script: &str, timeout: Duration) -> Captured {
    let mut command = std::process::Command::new("/bin/sh");
    command
        .args(["-c", script])
        .env_clear()
        .env("PATH", "/usr/bin:/bin");
    supervise(&mut command, timeout).unwrap()
}

#[test]
fn rejects_missing_malformed_and_negative_completion() {
    for value in [
        "",
        "not json",
        "{}",
        r#"{"metadata":{"status":"error"},"messages":[]}"#,
        r#"{"metadata":{"status":"completed","cost_usd":-1},"messages":[]}"#,
        r#"{"metadata":{"status":"completed"},"messages":[]}"#,
    ] {
        assert!(parse_completion(value).is_err(), "accepted {value}");
    }
}

#[test]
fn accepts_positive_upstream_json_with_known_cost() {
    let completion = parse_completion(r#"{"metadata":{"status":"completed","cost_usd":0.02},"messages":[{"role":"assistant","content":[] }]}"#).unwrap();
    assert_eq!(completion.turn_count, 1);
    assert_eq!(completion.spend_usd, 0.02);
}

#[test]
fn drains_both_pipes_past_capture_limit_without_deadlock() {
    let result = fixture(
        "head -c 2000000 /dev/zero & head -c 2000000 /dev/zero >&2 & wait",
        Duration::from_secs(5),
    );
    assert!(!result.timed_out);
    assert!(result.status.success());
    assert!(result.stdout.truncated && result.stderr.truncated);
    assert_eq!(result.stdout.bytes.len(), MAX_OUTPUT_BYTES);
    assert_eq!(result.stderr.bytes.len(), MAX_OUTPUT_BYTES);
}

#[test]
fn timeout_kills_group_and_returns_promptly() {
    let start = Instant::now();
    let result = fixture("sleep 30 & wait", Duration::from_millis(100));
    assert!(result.timed_out);
    assert!(start.elapsed() < Duration::from_secs(3));
}

#[test]
fn exited_parent_does_not_leave_grandchild_holding_pipes() {
    let start = Instant::now();
    let result = fixture("sleep 30 & exit 0", Duration::from_secs(2));
    assert!(result.status.success());
    assert!(start.elapsed() < Duration::from_secs(3));
}

#[test]
fn zero_exit_with_garbage_is_failed_receipt() {
    let output = fixture("printf 'not json'", Duration::from_secs(1));
    let receipt = finish(output, std::path::Path::new("."), Instant::now());
    assert!(matches!(receipt, Receipt::Failed { .. }));
}

#[test]
fn live_run_cannot_be_enabled_by_environment_flags() {
    assert!(
        run_goose(
            "never launch",
            std::path::Path::new("."),
            Duration::from_secs(1)
        )
        .is_err()
    );
}

#[test]
fn explicit_goose_binary_is_not_replaced_with_path_lookup() {
    let command = goose_command(
        std::ffi::OsStr::new("/configured/goose"),
        "hello",
        std::path::Path::new("."),
    );
    assert_eq!(command.get_program(), "/configured/goose");
    let explicit: Vec<_> = command.get_envs().collect();
    assert_eq!(explicit.len(), 1);
    assert_eq!(explicit[0].0, "PATH");
}
