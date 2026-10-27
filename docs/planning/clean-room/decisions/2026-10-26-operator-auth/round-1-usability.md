# Round 1 — usability response

Date: 2026-10-26. I maintain approval of the inert Unix-socket spike and opposition to privileged activation. The shared ledger supports that bounded choice; it does not establish human presence, MFA or deployed worker isolation. The wording below is a proposed interface contract, not an assertion that these checks have passed.

## Exact result contract

Use this success headline: **“Local socket transport checks passed.”** Follow it with three short, separate statements:

- **Verified:** “The test server accepted the expected OS peer identity and returned the diagnostic response.”
- **Synthetic denial coverage:** “Configured UID mismatch and unreadable-credential cases were rejected. This does not prove access denial for a deployed worker account.”
- **Unavailable:** “Factory mutations remain disabled. Human approval, deployed identity separation and independent emergency stopping are not verified.”

List actual test outcomes beneath those statements or in a linked evidence file. Do not compress every result into an “authentication passed” badge. If client-side kernel credentials were not checked, add **“Server identity: protected directory and ownership checks only; client-side peer-credential verification not performed.”** If they were checked on the actual diagnostic connection, report that exact fact. A separate probe connection must not be described as verification of the request connection.

For machine consumers, the corresponding fields should identify the narrow transport result, each named check, the synthetic nature of UID mismatch, the client-assurance method, and privileged capability state. Absent tests remain `not_run`; a missing result cannot become `pass`. These are project-specific reporting choices.

## Refusal wording and next steps

For a preexisting endpoint: **“Cannot start: the socket path already exists. Nothing was removed. Use a fresh private directory for this test.”** This gives an immediate safe action without asking the operator to delete an unknown file or socket.

For peer mismatch: **“Request refused: OS peer identity differs from the configured operator identity. Check the configured UID; do not relax access permissions.”** For credential-read failure: **“Request refused: the peer identity could not be verified. Review the diagnostic error; access remains denied.”** For a privilege attempt: **“Unavailable in this diagnostic spike. Approval and deployment gates are still open.”** None should suggest retrying through TCP.

The next-step report should distinguish engineering work from operator action. For this spike, engineering can complete failed transport tests. Choosing a human-authorization mechanism, provisioning distinct identities and demonstrating an independent watchdog remain later gated work, not instructions for the operator to improvise during an error.

## Maintained and conceded positions

I maintain that meaningful operation details belong in consequential approval, distinct from routine connection identity. This follows the ledger's OWASP transaction-authorization evidence. I maintain that UID checks cannot prove human intent; Apple's peer-credential semantics concern OS credentials. [Shared evidence and sources](evidence-ledger.md).

I concede that client-side peer-credential assertion need not block this **inert transport experiment** if the report explicitly states the protected-directory/server-ownership assurance and its limits. It remains a separate integration decision. Neither approach excludes same-UID replacement.

I also concede that a controlled endpoint-replacement test cannot prove all pathname-race resistance. Report that precise ordering under the trusted-directory assumption. Bound body size, idle time and concurrency as spike safeguards; label any untested load or denial-of-service claim a production proof gap. Concise wording must preserve these distinctions rather than conceal them.
