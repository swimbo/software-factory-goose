# Live-leader bounded capture spike

This is a disposable same-UID extension of the [live group leader experiment](2026-10-27-live-group-leader-spike.md), not production execution. A trusted group leader owns a fixed shell target, drains its separate nonblocking stdout and stderr fairly, retains at most 4096 bytes per stream, marks truncation, and sends a bounded versioned frame over its own separate output pipe. The target's stdin is null and its stdout/stderr are separate pipes; the experiment does not establish protection against a malicious same-UID process inspecting or attacking the leader.

`cargo run -p watchdog --example live_leader_capture_spike --locked --offline` passed twice; strict example Clippy passed. The final run verified:

- Both streams each emitted more than the cap, including forged status-like text. The parsed frame retained the true exit code 7, separate 4096-byte streams, and both truncation flags without deadlocking. Output was only examined after a checked group kill and leader reap.
- An injected `EPERM` was rejected while the live leader remained owned, followed by a successful actual group kill. This was an injected error, not a real cross-UID permission failure.
- A no-timeout control produced a delayed marker. A separate target was observed ready before a 150 ms frame timeout, after which the owned live group was stopped and the marker remained absent.
- A frame declaring a stream larger than the cap was rejected. A leader that exited after writing a truncated frame caused output refusal; no signal was sent after observing its death, and the finite synthetic child was allowed to finish without orphan PID signaling.

The parser and leader are a test harness, not a wired worker protocol. The fixture does not cover escaped sessions, guardian or supervisor crash, malicious same-UID descriptor inspection or process signaling, distinct identities, cancellation races, all malformed frames, output secret masking, reliable power-loss recovery, or cross-UID signaling. The owner check and subsequent kill are separate operations; any intervening failure remains unresolved. The truncation behavior is synthetic and must not be assumed safe for secret filtering. No existing service, account, VM, credential, or production worker was touched.
