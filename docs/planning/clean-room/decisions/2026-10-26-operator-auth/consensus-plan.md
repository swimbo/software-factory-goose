# Bounded operator transport consensus

Decision date: 2026-10-26. Three personas (application security, Rust operations, contrarian usability), one response round. **Consensus applies only to the inert Unix-socket verification spike.** It does not satisfy O4 full human authorization or activate any runtime route.

## Evidence and selected option

**ADEQUATE:** pinned Axum 0.8.9, Tokio 1.53.3, and reqwest 0.12.28 support a local Unix-socket diagnostic exchange; kernel peer credentials can identify the OS principal. See [source ledger](evidence-ledger.md) and [Rust source verification](research-rust-ops.md).

**INSUFFICIENT:** actual alternate worker identity, same-connection client authentication of the service, human intent/MFA, a trusted approval channel, durable atomic approval consumption, and independent emergency control. Evidence gaps remain gaps after consensus.

Select a peer-checked Unix socket in a private temporary directory using existing dependencies. Defer a loopback bearer because its secret lifecycle does not answer this narrow local need; defer OIDC/device flow because issuer, enrollment, recovery, and transaction semantics remain unselected. These are context-specific judgments, not claims that either alternative is inherently unsuitable.

## Exact experiment contract

- A reusable example exposes only an inert diagnostic response and denied/unavailable privilege response. It does not mount the factory router, access a database, invoke Goose, create identities, provision credentials, install services, or listen on TCP.
- Create a fresh private temporary directory and verify expected owner and mode. Refuse unsafe parents and every existing endpoint: regular file, symlink, live socket, or stale socket. Remove nothing to make binding succeed.
- Capture actual kernel peer credentials on accepted server connections. Deny failed lookup and wrong expected UID. Request-body UID or approval fields cannot override the connection identity or enable mutation.
- Client assurance for this experiment is verified directory/socket ownership and a harness-owned server. Pinned reqwest's UDS path does not expose peer credentials to the caller. Client-side credential verification on the actual HTTP connection remains not performed; a separate probe must not be described as equivalent.
- Record socket owner, type, device and inode after binding. Cleanup removes only a matching current object; changed or missing objects are preserved/treated explicitly. Test ordinary and repeated cleanup, plus replacement of the original pathname before cleanup. Verify the replacement remains connectable. Test regular-file/symlink replacement preservation.
- Claim only **controlled replacement preserved under the private-directory assumption**. Metadata-check plus unlink is not an atomic defense against active same-UID pathname replacement. Comprehensive race and same-UID compromise resistance remain unproven.
- Use a 30-second overall run deadline, two-second client request deadlines, at most 1 KiB diagnostic request bodies, and no more than four concurrent fixture connections. Sequential fixtures should ordinarily use one. These are experiment controls; they do not certify production denial-of-service resistance or slow-client handling.
- Run positive owner exchange; synthetic expected-UID mismatch; synthetic credential-lookup failure; forged body; oversized body; existing file/socket/symlink; unsafe parent; ordinary/repeated cleanup; controlled endpoint replacement. Do not call synthetic identity checks deployed worker denial.

## Reporting and acceptance

Headline on actual success: **Local socket transport checks passed.** Record each tested outcome. Separate verified expected-peer exchange, synthetic denial coverage, and unavailable privileged functions. Report client assurance as directory/ownership checks only. Unperformed checks are `not_run`; missing checks never become passed. Any failed check keeps the spike incomplete, with its error recorded.

A successful spike supports considering future routine transport integration. It grants no promotion, dispatch, budget, credential, worker-result, or brake authority. No fallback transport is permitted.

## Remaining gates

O4 remains OPEN: choose a trusted human-approval mechanism, bind repository/task/action/candidate/base/evidence/reason/audience/expiry/nonce, and prove atomic durable consumption plus execution-time validation under concurrency and restart. Distinct identities require real second-UID testing. Independent brake requires a separately supervised stop-only authority, registered child-group targeting, PID-reuse safety, rejection of ordinary credentials/arbitrary PIDs, and operation during main-service/database failure. Production connection admission, body/idle controls and service-authentication design remain integration work.

## Post-debate user decision (supersedes unresolved mechanism selection only)

The user explicitly selected: **Separate local operator account and action-bound approval channel; no MFA claim**. This is a human architecture decision after the scoped debate, not a new evidence claim or an expansion of spike results. O4's mechanism selection is resolved; operating verification and activation gates remain open. Implement a pure action-bound approval contract and feature-gated Restate virtual object with immutable nonce issuance and serialized single consumption. The configured issuer is not per-request authentication: issuance is valid only behind a separately verified kernel-authenticated operator adapter and private ingress. Leave the journal unregistered until that boundary is proven. Stored records are authoritative; submitted records cannot redefine them. Bind the exact operation, task, repository, target ref, candidate/base SHA, evidence digest, reason, audience, expiry and nonce. There is no MFA or resistance-to-same-UID-compromise claim.
