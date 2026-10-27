# Trusted spawn broker boundary — 2026-10-27

Status: bounded implementation and local transport/process proof; unregistered, no production activation. R9/G05 remain partial. No execution or Goose runtime files changed.

## Implemented boundary

`watchdog::broker` adds a separate `/launch` Unix router. Authentication requires the actual socket peer UID and a fixed-length credential checked with the existing constant-time primitive. Duplicate credential headers are rejected. Peer identity cannot come from JSON or forwarded headers. The brake router still exposes only `/stop`; the launch router has no stop, registration, admission, arbitrary command or PID endpoint.

Only trusted in-process code can construct and admit `ApprovedLaunch`. It is not deserializable or mutable and binds a pre-existing family, worker/Goose/tool role, absolute executable and working directory, exact arguments, child UID/GID and a maximum five-minute validity interval. The server issues an opaque canonical ULID; callers send only that ID. Admission stores a bounded immutable record; there is no update, reset or eviction operation. Eligibility/claim/evidence authority must be supplied by the trusted publisher, which is not implemented here.

A launch checks its validity and captured executable metadata plus working-directory identity. The registry rechecks expiry while holding the family admission lock. Executable replacement/modification rejects the launch. Metadata checks are not an atomic executable seal: protected deployment paths, ACL review and an OS-level immutable execution boundary remain required. The production admission path rejects writable/untrusted executable ancestry, but this alone does not settle those races.

The watchdog alone spawns and retains each `Child` and owns group signalling/reaping. Launch failure creates a permanent tombstone. A successful ID always returns the same receipt, including after family stop; that historical receipt is not fresh liveness or execution permission. Stop closes family admission atomically. Neither response loss nor repeated requests can create a second child for an ID in this process lifetime. Registry/broker restart recovery is not provided.

Request bodies are limited to 1024 bytes. Request handling has a four-second timeout, blocking launch wait a three-second timeout, and one outstanding launch permit. A timeout reports unknown outcome and requires retrying the same ID; it never asserts nonexecution. A blocking OS spawn still holds registry admission; an OS-level hang can delay stop. No bounded independent stop SLA is claimed for that case.

## Actual checks

- Test-first RED: missing `watchdog::broker` APIs; `/tmp/sfactory-broker-red.log`.
- `cargo test --locked --manifest-path clean-room/Cargo.toml -p watchdog --all-features`: **12 unit + 4 integration tests passed**, zero failures/ignored. `/tmp/sfactory-broker-green.log`.
- Default-feature tests also passed (8 unit tests; fixture integration tests are intentionally feature-gated). `/tmp/sfactory-broker-default.log`.
- Strict all-feature/all-target Clippy: passed. Scoped rustfmt and diff checks passed.
- Real Unix listeners and kernel peer credentials: valid synthetic credential admits only the configured actual peer. A different configured adapter UID rejects the actual connection despite forged header/body UID and a correct credential. No accounts are created.
- Broker launches three private process groups from fixed server-side shell fixtures. The worker writes its own PID, suspends itself with SIGSTOP, and is observed in stopped state with read-only `ps`. Goose/tool stand-ins run private group descendants. The test reads both descendant PIDs and verifies their group membership. All three groups are stopped through a separate authenticated brake listener; all leaders report SIGKILL/reaped and all registered groups and all five fixture process IDs are observed absent. These are stand-ins, not actual Goose or execution binaries.
- Wrong/cross-path credentials, duplicate credential headers, oversized body, forged command/UID fields, unknown launch and closed-family launch reject. Dropping a successful HTTP response then repeating the same ID yields one group and its original receipt. Replaying after stop does not create a process. Launch router does not expose `/stop`.
- Expired approval, changed executable and restored-after-rejection executable all fail without spawning; identity overlap/empty child policy reject; fixture instances cannot produce the production router.

Only disposable children, private test directories/sockets and synthetic keys were used. The initial assertion expected unauthenticated unknown-route 404 but auth correctly returned 403; the test now authenticates before checking route absence. Its already-stopped fixture directory was removed explicitly. Subsequent fixtures clean their own known files; no standing service, existing process, real credential, model call or system account was touched.

## Remaining activation and integration gates

Production identities must distinguish watchdog, trusted launcher adapter, brake and child accounts. The ordinary non-root watchdog cannot currently establish another child UID/GID and clear supplementary groups. Its pre-exec identity transition fails closed instead of silently running model code as watchdog. Distinct-UID children also require narrowly scoped signal authority. A reviewed OS launcher/containment design and provisioned identities must solve both spawn and stop authority; granting general privilege is not implemented or approved by this change. The local design limitation matches Apple’s primary [setuid/setgid](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/setuid.2.html) and [setgroups](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/setgroups.2.html) permission contracts; no privileged transition was attempted on the host.

Execution currently owns its tool subprocess stdin/stdout, process group and wait lifecycle. The new broker retains null stdio and has no safe output/result transport. Actual integration must transfer spawn **and** sole-reap authority together; adding an external waiter to execution would be incorrect. `run_goose` remains blocked. The broker has no trusted journal eligibility publisher, durable launch-ID recovery, lease-bound lifecycle timeout, cancellation/output protocol or policy-pinned request delivery yet.

Unregistered descendants that call `setsid`/`setpgid` remain outside the owned group guarantee. File descriptor/sandbox/network isolation, executable sealing, inherited credential exclusion, protected listeners, independent service supervision, crash recovery and realistic hung-kernel-spawn behavior remain unverified. This fixture does not pass the complete factory kill-switch or production worker integration gates.
