# Socket spike results

Run date: 2026-10-26. Host: `ba-2.local`, macOS/aarch64. Actual kernel-reported peer UID: **501**.

Command: `cargo run --locked -p control-plane --example verify_operator_socket`, from `clean-room/`. Result: **PASS**. Reusable source: `clean-room/crates/control-plane/examples/verify_operator_socket.rs`. Initial compile identified reqwest's `&PathBuf` argument incompatibility; corrected to `&Path` and the actual run passed.

The harness used a newly created private temporary directory, an inert Unix listener and existing dependencies. No factory routes, database, Goose process, TCP listener, new account, persistent service, or external credential was used. The harness verified removal of its empty temporary directory.

Passed checks:

- Actual server-side kernel peer credential and diagnostic exchange.
- Forged UID/approved request fields cannot alter identity or enable privilege.
- 1 KiB request-body limit (oversized request rejected).
- Existing live/stale socket, regular file, and symlink refused without removal.
- Unsafe parent mode and unexpected owner refused.
- Ordinary and repeated cleanup.
- Synthetic configured-UID mismatch and synthetic credential-read failure denied.
- Controlled socket/file/symlink replacement preserved; replacement socket remained connectable.
- Private temporary directory removed after fixture cleanup.

Controls: 30-second overall deadline, two-second client request deadline, 1 KiB JSON body limit, sequential fixture concurrency one.

**Scope:** Local socket transport checks passed. The denial tests do not prove actual deployed worker-account exclusion. Client assurance was directory/socket ownership only; actual-request client-side peer credentials were not checked. Cleanup is not proven atomic against hostile same-UID pathname races. Production admission/slow-client resistance, human approval, distinct deployed identities, real Restate replay, and independent brake were not tested. Privileged operations stayed unavailable.
