# Usability position — authorize a socket spike, preserve the approval boundary

Date: 2026-10-26. Read: shared evidence ledger and all three research briefs. Recommendation: **approve the bounded Unix-socket spike; do not activate privileged mutation routes**. Evidence is **ADEQUATE** for selecting routine local transport and **INSUFFICIENT** for human-presence, MFA, deployed identity separation or an independent brake. This distinction is part of the product contract: the operator must understand which capability has been demonstrated.

## Recommendation and rationale

For one operator on one Mac, routine CLI access should use a private Unix socket with kernel peer-identity checks. The operations brief confirms the pinned Axum, Tokio and reqwest stack can support this without adding a separate networking framework. The usability benefit is concrete: the operator does not copy a bearer token into a shell, decide where to save it, or repair expired credentials merely to inspect local state. Setup still requires correct ownership, permissions and explicit endpoint configuration. That complexity is acceptable when installation can diagnose it once and ordinary commands can thereafter remain simple.

This recommendation concerns routine transport only. Apple's peer-credential API establishes the OS principal at connection; it does not distinguish the operator's CLI from malicious software running with the same principal. The security brief is right to reject UID-plus-local-secret as an MFA claim. The approved spike must make this limitation visible in its result and leave consequential operations unavailable. [Apple peer credentials](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man3/getpeereid.3.html).

I oppose adding a loopback bearer merely because HTTP examples are familiar. That replaces a kernel-provided local identity with another reusable secret lifecycle while leaving the critical human-approval question unanswered. RFC 6750 makes possession the basis of bearer authority. This is manageable when integrations need it, but today's requirements do not establish that need. [RFC 6750](https://www.rfc-editor.org/rfc/rfc6750.html).

I also oppose selecting an OIDC provider during this narrow implementation gate. It may become the right choice for remote operators or organization-managed identity. Device flow has useful human interaction and expiry semantics, yet also requires a provider, enrollment, browser interaction and recovery policy; the RFC discusses remote phishing. Those costs should follow an explicit operational requirement. They should not become a hidden dependency of local status inspection or emergency stopping. [RFC 8628](https://www.rfc-editor.org/rfc/rfc8628.html).

## Strengths and concerns

The panel's emerging separation of routine identity, transaction authorization and emergency control is strong. Each has different availability and authority needs. It permits a usable CLI without pretending an authenticated connection can authorize every future action. It also keeps the brake meaningful when the main service is hung or unreachable.

My concern is that this separation could produce three competing setup experiences, opaque error codes and too many confirmations. A developer-facing explanation of sockets, credentials and journals should not become the operator's daily flow. Status should say what can be done and which concrete prerequisite is missing. For example: “Promotion unavailable: independent approval is not configured” is more actionable than a generic 403 or a claim that the task is ready.

Another concern is habitual approval. Asking for confirmation on every inspection or harmless local preview trains a user to respond without reading. My proposed interface reserves explicit transaction confirmation for actual consequential actions. The confirmation should name its action and destination and show a concise change summary, exact revision references, evidence state and expiration. Longer technical evidence remains available through a separate inspection command. This is my interface judgment, informed by OWASP's meaningful-transaction-data principle, rather than a prescribed layout. [OWASP transaction authorization](https://raw.githubusercontent.com/OWASP/CheatSheetSeries/master/cheatsheets/Transaction_Authorization_Cheat_Sheet.md).

## Missing evidence

No source proves the intended worker UID is deployed here. A synthetic mismatched expected UID tests a branch in the program; it does not prove the real generator cannot read the socket directory or approval material. The deployment test must eventually use a genuinely different principal. The current operator-owned process cannot supply that proof by asserting a name.

The approval mechanism is still unselected. We have no trusted display, proof of human presence, durable single-use consumption, or recovery procedure. Short expiry alone would not establish any of these. Likewise, a second stored credential is not evidence that an attacker compromising the ordinary credential cannot obtain it. These are explicit blockers for privileged activation, not polish items to defer after opening the route.

## Concrete changes and bounded spike

Implement the temporary-directory socket prototype with the existing dependencies. Verify parent ownership and private mode, reject unsafe existing entries, and fail closed when peer credentials cannot be read. Test expected-owner success, configured-peer mismatch, duplicate startup, regular-file and symlink collisions, stale socket refusal, and cleanup that cannot remove a replacement endpoint. The prototype should print a small result record identifying which checks passed and which deployed-identity checks remain untested.

Keep its request surface inert: a health/read response is enough. Do not add a fallback to unauthenticated TCP when setup fails. An explicit endpoint error is the correct experience because silently changing transport changes the operator's security expectations.

In the later approval spike, test the user's preview against server-held state, changed candidate/base, replay, expiration and simultaneous submissions. Preserve a readable expired preview while requiring fresh authorization; do not silently approve the newest candidate. In the later brake spike, test a harmless registered child group with the main service unavailable and report observed termination separately from acceptance.

## Hard stances

No privilege activation from socket transport success. No claim that a typed confirmation or two local secrets is MFA. No same-UID synthetic test presented as deployed separation. No emergency stop dependent on the main service or an identity-provider response. No hidden network fallback or destructive socket cleanup. Within those boundaries, proceed autonomously with the socket spike and retain the existing runtime mutation block.
