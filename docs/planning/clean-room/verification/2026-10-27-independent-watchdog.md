# Independent brake/watchdog component — 2026-10-27

Scope: partial G-05/R9 implementation. Added independent `watchdog` workspace crate and an explicitly opt-in `sf-watchdog-fixture` binary (`fixture` feature). There is no production serve mode, main registration, sfctl integration, existing-process registration, or runtime activation. No standing service, existing user process, system account or real credential was targeted.

## Implemented contract

The crate has no control-plane, Restate, Postgres, gateway or credential-broker dependency. Its Unix HTTP surface exposes only `POST /stop` with an opaque registry target ID. There is no caller-selected PID/PGID, launch command or registration route. Unknown JSON fields, malformed IDs and unowned targets fail closed.

Authentication requires both the accepted socket's actual kernel UID and a separate 32-byte brake credential. Production policy requires distinct non-root watchdog/brake identities and explicit exclusions for ordinary control-plane/operator/generator/evaluator identities. The public router checks its configured service UID against the kernel process identity. The credential is neither Debug nor Serialize, uses `subtle::ConstantTimeEq` for its fixed-size secret comparison, and has no ordinary operator-token fallback. Duplicate credential headers deny. The fixture receives only a synthetic credential over inherited stdin, never argv, environment or logs.

Registry admission is a trusted in-process launch API: it spawns and retains its own `std::process::Child`, forces a new process group, clears environment and closes stdio. It never accepts ownership of a preexisting numeric PID. At most 64 records are retained; IDs/tombstones never evict or reset. This is not a production launcher or worker isolation proof.

Before signalling, the registry requires default SIGCHLD behavior with no auto-reap and verifies its child relationship using `waitid(WNOWAIT)`. It deliberately does not call `wait` or `try_wait` before the group signal, so even a naturally exited leader retains its PID ownership. On macOS, `getpgid` alone rejects zombies with ESRCH; the initial regression exposed that and was corrected with the non-reaping child check. Live leaders must still belong to the originally created group.

It sends `SIGKILL` to that owned negative group ID once, then reaps the leader. After any attempt/reap, it never sends another nonzero signal for the target. Group absence is observed with signal zero, and a potentially reused group ID produces an unverified/incomplete response rather than another kill. HTTP 200 requires both leader reap and observed group absence; incomplete work is 202, and faults/timeouts make no termination claim. Exact repeat stop returns the retained result. Registry shutdown cleanup is best effort and is not reported as completed stop.

Parsed bodies are capped at 1 KiB, request processing at four seconds, stop observation at two seconds, and concurrent stop work at one operation. The fixture independently times out and performs owned-child cleanup. Header-level slow-client and whole-service admission limits still require production server integration.

## Verification

Test-first RED: missing implementation compilation failed with four unresolved-type errors (`/tmp/sfactory-watchdog-red.log`). A later natural-leader-exit test failed because macOS `getpgid` does not identify an unreaped zombie; the ownership check was corrected before GREEN. Early failing shell fixtures used bounded 60-second sleep descendants; no numeric-PID recovery kill was attempted after losing the parent ownership handle.

GREEN:

- `cargo test --locked --manifest-path clean-room/Cargo.toml -p watchdog --all-features`: **6 unit tests + 1 separate-process integration test passed**, no failures or ignored tests (`/tmp/sfactory-watchdog-green.log`).
- `cargo clippy --locked --manifest-path clean-room/Cargo.toml -p watchdog --all-features --all-targets -- -D warnings`: passed.
- Scoped rustfmt and `git diff --check`: passed.

Unit tests cover unowned target rejection, credential/identity mismatch, actual owned-child termination and repeat stop, a naturally exited unreaped leader with a living descendant, real Unix peer mismatch despite a forged identity header, missing connection metadata, and post-reap numeric-ID reuse fault injection. The reuse test substitutes another fixture-owned group ID into an already-reaped record and confirms the survivor is not signalled; it does not claim to force real OS PID recycling.

The black-box test launches a separate watchdog executable, which itself launches a harmless leader and descendant in one group. It verifies their actual group membership, stops two owned sleep-process dependency stand-ins, and successfully authenticates/stops the worker group without starting a control-plane or database. It checks leader SIGKILL/reap, descendant disappearance and group absence; rejects an ordinary-token substitute, forged PID field, unknown target, registration route, duplicate credential headers and oversized body; observes a stalled body return 408; and verifies exact repeat-stop output. This is independence from absent application dependencies, not a claim that real production services were deliberately brought down.

Positive fixture authentication intentionally runs under the current UID behind the explicitly named fixture feature. Public production policy has no same-UID mode. Thus actual peer lookup is proven, while distinct deployed accounts, credential-channel protection and human presence/MFA are not.

## Limits and activation gates

No brake account/key provisioning, protected production socket/group configuration, independent service supervision, worker launch integration or CLI path is enabled. The registry is memory-only and cannot recover ownership after watchdog crash/restart. Do not reconstruct it from saved numeric PIDs. The dedicated process must remain the sole child reaper; embedding it with another reaper violates the ownership contract.

Process-group termination does not prove containment of a descendant that escapes with setsid or changes group. The tested descendants remain in their owned group. Prevention/recovery of escaped descendants, watchdog-death handling, durable lifecycle coordination and distinct-UID permission behavior remain blockers. The component reports observations, not universal process-tree containment. G-05/R9 remains partial.

## Source basis

Rust documents that dropping `Child` does not wait or terminate it and that waiting reaps an exited process; the implementation keeps the child unreaped until signalling finishes. [Rust Child documentation](https://doc.rust-lang.org/std/process/struct.Child.html).

The negative-ID group-signal operation follows the OS contract; it does not reach processes outside that group. [Apple kill(2)](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/kill.2.html), [Apple wait(2)](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/wait.2.html).

## Follow-up: multiple process groups

The single-group results above do not cover execution/Goose/tool processes that create other groups. The component now supports a directly owned family with atomic admission closure and per-group results; an actual three-group/six-process fixture passes with the worker stand-in suspended. Actual worker/Goose spawn-broker integration and escaped-descendant containment remain blocked. See [family verification](2026-10-27-watchdog-family.md); do not treat this component as a factory kill-switch pass.
