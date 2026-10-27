# Moderator disagreement brief — round 1

Date: 2026-10-26. Inputs: [evidence ledger](evidence-ledger.md), [AppSec position](position-appsec.md), [Rust operations position](position-rust-ops.md), and [usability position](position-usability.md).

## Decision and evidence boundary

All three reviewers recommend a bounded Unix-socket experiment using the pinned libraries. The evidence is **ADEQUATE for this routine local transport choice and its feasibility spike**. This is project-specific engineering judgment supported by verified API availability, not a standards mandate. It does not yet authorize integrating the real factory router.

Evidence remains **INSUFFICIENT for choosing a completed privileged human-authorization mechanism, enabling consequential mutations, claiming deployed worker isolation, or declaring the independent brake ready**. Agreement about desired properties cannot substitute for selecting and testing those mechanisms. Those questions remain open after this debate.

## Agreements

- Use an isolated private temporary directory and inert diagnostic/read route. Do not attach the database, invoke Goose, change identities, or start a persistent service.
- Verify kernel peer identity; reject missing/unreadable credentials, forged body identity, and configured UID mismatch. Label the mismatch test synthetic.
- Refuse all preexisting endpoint paths for the spike, including stale sockets. Do not copy the upstream example's unconditional unlink or credential unwrap. [API example](https://github.com/tokio-rs/axum/blob/main/examples/unix-domain-socket/src/main.rs).
- No automatic TCP fallback, bearer-secret provisioning, OIDC enrollment, or activation of promotion, dispatch, credential, budget, brake, or worker-result mutation.
- UID establishes an OS principal, not human intent. Transaction approval requires separate execution-bound authorization. Two stored secrets are not evidence of distinct MFA factors. [Ledger sources](evidence-ledger.md).
- Keep the brake separately supervised and stop-only in the later design. A received request or graceful-shutdown signal is not observed process termination.

## Contested or underspecified decisions

There is **no material opposition to the bounded transport spike**. The following implementation contracts need one response round; they are not resolved merely because positions use similar language.

**Client assurance:** AppSec asks how the client knows the intended service; usability mentions checking both peers, while the immediate operational spike centers on server-side peer checks. The panel must state whether protected-directory/server ownership checks are sufficient for this experiment or a client-side kernel credential assertion is mandatory. Neither excludes same-UID replacement.

**Cleanup assurance:** All positions demand that cleanup not delete a replacement endpoint. A controlled replacement test demonstrates one ordering, not freedom from every pathname race. The accepted claim must specify the trusted-directory assumption and distinguish deterministic inode/path checks from resistance to an active same-UID attacker.

**Acceptance wording and limits:** AppSec raises body-size, idle-connection, and concurrency limits; usability asks for a concise result. Decide which are bounded spike controls and which remain production proof gaps. A single “authentication passed” label would collapse these distinctions.

## Remaining proof gaps

Actual second-UID access denial; service/worker identity provisioning; trusted approval presentation and human intent; candidate/base/evidence binding at execution; durable atomic nonce consumption under concurrency and restart; watchdog authority, supervision, process registry, PID-reuse safety, and operation during main-service/database failure. No position supplies operating evidence that closes these gaps.

## Targeted response questions

1. **AppSec:** Define the minimum server-authentication and availability controls required for this inert spike. Which checks may remain explicitly deferred without weakening its narrow claim?
2. **Rust operations:** Specify safe bind/cleanup behavior and the exact replacement test. State which pathname-race guarantees remain unproven, and whether the existing reqwest client exposes peer credentials directly.
3. **Usability:** Propose a concise result contract that communicates local transport success, synthetic-denial coverage, and unavailable privileged functions without implying deployed isolation or human authorization.

After responses, the moderator may declare consensus only on the bounded spike contract. Privileged authorization selection and deployment readiness must retain their insufficient/open status.

## Round 1 resolution

**CONSENSUS_REACHED for the inert transport spike only.** Client assurance is RESOLVED: protected-directory/socket ownership checks suffice for the experiment; actual-request client-side peer credentials are deferred. Cleanup wording is RESOLVED: preserve controlled replacement under the private-directory assumption, with no atomic race-freedom claim. Availability/reporting is RESOLVED: bounded fixture controls and explicit synthetic/not-run/unavailable result fields. Privileged human authorization (O4), deployed identity isolation and independent brake remain OPEN/INSUFFICIENT, not consensus-complete. See `consensus-plan.md` and the three `round-1-*.md` responses.
