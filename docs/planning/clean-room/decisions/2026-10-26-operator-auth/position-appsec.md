# Application security position

Date: 2026-10-26. Inputs: shared evidence ledger and all three research briefs. Decision requested: a bounded transport spike. No live authority, service provisioning, or privileged mutation is authorized by this position.

## Recommendation and evidence grade

Approve the isolated Unix-socket spike, with the acceptance conditions below. Evidence is **ADEQUATE** for API feasibility and a local routine-access experiment, **INSUFFICIENT** for deployed isolation, human transaction authorization, or emergency-brake readiness. I agree with Rust operations and usability on that narrow conclusion. I oppose collapsing these grades into a single “authentication complete” milestone.

The strongest evidence is checkout-specific: the installed Axum, Tokio, and reqwest versions support the proposed transport without a replacement HTTP stack. Apple's peer-credential description and Tokio's macOS implementation support checking an OS principal. They do not distinguish a person from malware under that principal. [Rust operations research](research-rust-ops.md), [Apple peer credentials](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man3/getpeereid.3.html).

The spike should expose an inert diagnostic response and synthetic denied-mutation response. It should not mount the real factory router, attach a database, invoke Goose, change identities, or register a background service. A successful result authorizes considering routine transport integration; it does not enable any promotion, budget increase, credential issue, worker-result callback, or runtime dispatch.

## Strengths of the proposed direction

Unix sockets fit the verified single-host context and avoid adding an ordinary bearer credential lifecycle merely to identify the operator's local process. Existing client/server libraries reduce the implementation surface. A protected directory plus peer checks also produces understandable diagnostics: incorrect owner, unexpected peer, occupied path, and unsupported credential lookup can each fail explicitly.

The usability brief correctly separates routine inspection from consequential decisions. Step-up prompts on every status request would create friction without fixing the principal threat. A readable preview and an explicit action are useful interface requirements. They remain distinct from proof that an uncompromised human authorized the exact action.

The shared ledger also correctly treats the upstream example as API evidence rather than a deployment template. Its unconditional path removal and credential unwrap must not be copied into an operational listener. That distinction prevents a convenience example from quietly becoming the lifecycle policy.

## Concerns and contested assumptions

First, “owner-only” needs a precise object and principal. A directory owned by the operator and inaccessible to other UIDs excludes a distinct worker account; it excludes no process already running as the operator. UID matching cannot establish MFA. NIST's distinct-factor requirement is relevant to that terminology, not evidence that this project has achieved an assurance level. [NIST SP 800-63B-4](https://pages.nist.gov/800-63-4/sp800-63b.html#aal2).

Second, a configured mismatch test proves a conditional branch, not deployed separation. I contest any acceptance language that calls it a “worker denied” test without an actual worker-identity connection. Label it a synthetic mismatch. Actual cross-UID proof remains blocked until provisioning is separately selected and authorized; this does not block the bounded spike.

Third, server authentication deserves attention. Checking the client's UID alone does not prove the CLI reached the intended service. The protected parent directory and expected service owner must form part of the design. Same-UID socket replacement remains a documented threat limitation, even when a client-side credential check also passes.

Fourth, credential-read failure must deny without panicking the listener. Request size, idle-connection lifetime, and concurrency limits also matter: an authenticated local process can otherwise exhaust a service. The spike need not solve production availability, but it must expose these limits as unfinished rather than imply access control settles availability.

## Concrete changes to the spike contract

Use a fresh private temporary directory with an explicit expected UID and restrictive modes. Verify ownership and file type before bind. Refuse existing regular files, symlinks, sockets, and an unexpected parent; do not silently delete them. Conservative refusal is sufficient for this experiment. Automatic stale-socket recovery can be a separate decision requiring proof of ownership and liveness.

Test successful owner access, synthetic mismatch, credential-lookup error, forged UID fields, duplicate start, unsafe preexisting paths, and cleanup. Cleanup must remove only the socket created by that instance; an inode/path replacement test should confirm it cannot unlink another instance's socket. Preserve explicit error reasons without dumping environment or secrets.

Keep privileged requests unavailable irrespective of peer acceptance. Test that changing a request body, adding an “approved” flag, or supplying an operator UID cannot turn the diagnostic server into a mutation path. Record platform, actual UID, library versions, test results, and limitations in the artifact.

## Missing considerations and hard stances

Transaction approval needs a separate design record. My proposed fields include repository identity, task, action, candidate SHA, destination/base revision, evidence digest, reason, audience, expiry, and nonce. These are project judgments applying OWASP's execution-bound authorization principles. A preview must reflect server-held immutable data; changes require a new decision. Atomic durable consumption and mutation ordering must survive concurrency and restart. [OWASP transaction authorization](https://raw.githubusercontent.com/OWASP/CheatSheetSeries/master/cheatsheets/Transaction_Authorization_Cheat_Sheet.md).

A second readable token is not an independent human factor. A typed confirmation is not a trusted external display. A received stop request is not proof of termination. A separate watchdog sharing all failure dependencies with the main service is not independent. These are hard boundaries for wording and implementation.

The brake must retain narrowly scoped stop authority when the main service and databases are unavailable, and reject arbitrary caller-supplied PIDs. Its process registry, restart behavior, and resistance to PID reuse need explicit tests. This follows existing R9; the transport spike cannot discharge it.

I support proceeding now with the bounded experiment. Keep privileged routes disabled and readiness visibly partial until the remaining mechanisms are selected and their actual operating boundaries are verified.
