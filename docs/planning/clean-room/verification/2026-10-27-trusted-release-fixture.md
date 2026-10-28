# Inherited-group trusted result-release fixture

The example was subsequently refactored to use the [reusable guarded-release fixture](2026-10-27-reusable-guarded-release.md); its current invocation requires `--features fixture`.

This disposable fixture connects the real feature-gated `execution --fixture-inherited-tool-request` to an owned live group leader. The leader captures the execution JSON through a bounded pipe and sends it to a separate launcher as a length-prefixed frame. The launcher bounds the frame, checks it still owns a live leader in the expected group, successfully signals that group, reaps the leader, and observes group absence before returning the bytes to its caller. A deadline while waiting for group absence returns an unresolved error; no nonzero signal is sent after reaping.

The initial test failed with no guard implementation. An intermediate implementation correctly refused because group absence was not yet observable immediately after reap; the final version waits up to two seconds using observation only. `cargo build -p execution --features fixture-inherited-group --locked --offline`, strict example Clippy, and `cargo run -p watchdog --example trusted_release_fixture --locked --offline` passed. The fixture verified:

- Split synthetic credentials on stdout and stderr were masked by the actual execution boundary. Status-like text in target stdout remained output content; JSON was parsed by the launcher only after successful group cleanup.
- An injected `EPERM` returned no result bytes and retained the live leader for later cleanup. A frame declaring more than 4096 bytes was refused. A leader that exited after transmitting a complete result produced no release and was reaped without a group signal.
- A no-timeout positive run wrote its delayed marker. In the timeout run the synthetic child was observed ready, the launcher timed out and stopped its owned group, and the delayed marker stayed absent.

This is not an authenticated or durable production launcher. The feature argument and parent check can be spoofed by a same-UID process, and target or leader access to private descriptors is not proven against hostile same-UID code. Group absence does not establish that `setsid` descendants stopped. Leader or supervisor death, separate accounts, independent brake integration, blocked spawn, real Goose wiring, cancellation races, durable quarantine and recovery are still open. The finite synthetic commands and only directly owned group leaders were used; no VM, service, account, credential, or unrelated process was touched.
