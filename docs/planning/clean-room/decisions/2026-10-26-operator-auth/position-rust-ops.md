# Position paper: Rust operations

Date: 2026-10-26. Reviewed the shared evidence ledger and all three research briefs. This position recommends an isolated experiment, not privileged activation.

## Recommendation and assessment

Choose the **bounded Unix-socket spike** using the already pinned Axum, Tokio, and reqwest stack. Evidence is **ADEQUATE** for that experiment and **INSUFFICIENT** for production mutation, human-presence claims, or MFA. Keep promotion, budget increases, privileged credentials, and the real brake unavailable until their separate authorization and operating proofs exist. This follows the [shared ledger](evidence-ledger.md), not an assumption that a working HTTP server establishes authority.

The proposed direction is sound only if transport identity, transaction authorization, and emergency control stay distinct. A kernel UID check is a useful local boundary. It cannot identify whether Bo or a program running as Bo requested a merge. A second secret readable by that same principal does not repair the distinction. AppSec and usability correctly reject that shortcut; operations should not reintroduce it as an expedient implementation detail. [AppSec research](research-appsec.md), [usability research](research-usability.md).

## Evidence-backed rationale

There is no framework compatibility obstacle requiring another HTTP stack. Installed Axum 0.8.9 implements `Listener` for Tokio `UnixListener`; Tokio 1.53.3 implements macOS peer credentials through kernel calls; reqwest 0.12.28 already offers `ClientBuilder::unix_socket`. These facts were checked against the project's lockfile and installed source, with online API corroboration. The small experiment can exercise real pinned libraries without dependency migration. [Rust operations evidence 1–5](research-rust-ops.md), [Axum Listener API](https://docs.rs/axum/latest/axum/serve/trait.Listener.html).

The upstream example is not a secure lifecycle recipe. It unconditionally removes the socket path and unwraps peer-credential reads. Borrow the connection-information mechanism, then replace those assumptions with explicit rejection paths. [Axum example](https://github.com/tokio-rs/axum/blob/main/examples/unix-domain-socket/src/main.rs).

## Strengths

First, the ledger narrows this decision to a single-host transport rather than combining it with an identity-provider rollout. That makes success observable: a request either arrives through the expected socket with an acceptable kernel principal or is denied.

Second, the reviewers preserve transaction-specific approval. OWASP requires meaningful transaction data, a final execution check, expiry, and unique authorization. The proposed task/SHA/action binding maps those requirements to the factory, while leaving the exact trusted authorization mechanism unresolved. [OWASP](https://cheatsheetseries.owasp.org/cheatsheets/Transaction_Authorization_Cheat_Sheet.html).

Third, the existing independent-brake requirement prevents a misleading “stop accepted” response from being mistaken for termination. The operations result must be a registered child group actually killed and reaped, even if the main service is unavailable. That is project consensus R9, not a feature implied by Axum.

## Concerns, ranked

**Critical: same-principal execution collapses the boundary.** The verified environment has not established separate worker identities. A synthetic mismatched UID tests comparison logic, not that a deployed worker lacks operator privileges. Keep those two assertions separate and require a real second-UID attempt before claiming isolation. Kernel-reported peer credentials describe an OS principal, not human intent. [Ledger identity evidence](evidence-ledger.md).

**Critical: approval can be consumed before its decision is durable.** A mutex or in-memory nonce set loses replay protection on restart. The eventual design needs an atomic durable authorization-consumption and mutation-decision record, plus a final candidate/base check. Otherwise a second submission after a crash can reuse authority or execute against changed state. The exact persistence boundary must be designed; a socket spike cannot settle it. [OWASP execution/uniqueness guidance](https://cheatsheetseries.owasp.org/cheatsheets/Transaction_Authorization_Cheat_Sheet.html).

**High: careless socket cleanup can detach a healthy service.** “Remove if exists” does not distinguish stale sockets, active listeners, symlinks, or regular files. For this bounded spike, refuse every preexisting path. Production stale recovery is a separate design requiring ownership, object-type, active-listener, and race analysis. Reject credential-read failures rather than panicking. [Upstream example and installed APIs](research-rust-ops.md).

**High: a sibling task is not an independent watchdog.** Axum graceful shutdown waits for active connection tasks. An emergency path inside the main process still shares its failure domain. The watchdog must be separately supervised, stop-only, and independent of main-service and database availability. Ordinary operator authority must not grant arbitrary PID targeting. [Shutdown source and R9 analysis](research-rust-ops.md).

**Medium: hidden fallback weakens operator diagnosis.** If the socket fails, silently trying unauthenticated TCP converts an availability problem into an authority change. Return an actionable error identifying the failed socket or credential check. Do not add a bearer fallback during this spike. This is an operational recommendation derived from the declared deny-by-default boundary.

## Missing considerations and concrete changes

Record the expected operator identity, server identity, socket ownership, and parent-directory ownership as separate configuration facts. A client should know which service it reached; protected directory ownership limits substitution, but same-UID compromise remains explicit. Avoid copying a UID from request JSON into trusted connection metadata. [Usability evidence U1](research-usability.md).

Implement only a harmless identity/status route in a private temporary directory. Verify directory and socket modes, successful owner access, configured wrong-UID denial, unavailable credentials, duplicate startup, regular-file/symlink refusal, bounded shutdown, and cleanup of only the created socket. Record the host and dependency versions. Use a fixture for unavailable credentials and label that result synthetic.

Then write separate transaction and watchdog test plans: changed SHA/base/action, expiry, concurrent replay, replay after restart, a frozen main service, and rejection of an unregistered process target. Do not run those against live factory work. A real alternate identity and separately supervised watchdog remain prerequisites, not implied follow-on authorization.

## Hard stances

1. No privileged activation from a passing socket test.
2. No same-UID authentication described as human presence, MFA, or worker isolation.
3. No unconditional socket unlink, silent TCP fallback, or success response that outruns the observed action.
