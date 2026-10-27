# Application security research

Research date: 2026-10-26. Persona: application security. This is evidence and a proposed position for debate, not an adopted architecture or implementation authorization.

## Eight source-backed facts

1. Authentication establishes identity; authorization separately decides permitted actions. Every request needs authorization, with denial as the default. A successful CLI login cannot by itself authorize promotion. [OWASP Authorization](https://raw.githubusercontent.com/OWASP/CheatSheetSeries/master/cheatsheets/Authorization_Cheat_Sheet.md)
2. Transaction approval must show the significant operation details and distinguish approval from ordinary login. OWASP specifically considers a compromised user computer, so a local confirmation prompt alone cannot prove a human approved the displayed transaction. [OWASP Transaction Authorization, 1.1/1.4](https://raw.githubusercontent.com/OWASP/CheatSheetSeries/master/cheatsheets/Transaction_Authorization_Cheat_Sheet.md)
3. Approval requires server-side enforcement, controlled state transitions, and a final execution check. Changing transaction details must invalidate the previous approval. [OWASP Transaction Authorization, 2.1/2.5/2.6/2.8](https://raw.githubusercontent.com/OWASP/CheatSheetSeries/master/cheatsheets/Transaction_Authorization_Cheat_Sheet.md)
4. Expiry and per-operation uniqueness alone do not stop repeated use of the same approval: consumption must be atomic and shared across accepting instances. [OWASP Transaction Authorization, 1.5](https://raw.githubusercontent.com/OWASP/CheatSheetSeries/master/cheatsheets/Transaction_Authorization_Cheat_Sheet.md)
5. NIST AAL2 requires two distinct authentication factors. Two stored bearer secrets do not establish those factors; neither does a Unix peer UID plus another file readable by that UID. This project should avoid an MFA claim without a specific conforming mechanism. [NIST SP 800-63B-4, section 2.2](https://pages.nist.gov/800-63-4/sp800-63b.html#aal2)
6. Replay resistance requires freshness beyond transport protection. NIST describes challenges/nonces and explicit authentication intent; a fresh channel does not make a stolen reusable credential single-use. [NIST, sections 3.2.7–3.2.8](https://pages.nist.gov/800-63-4/sp800-63b.html#replay)
7. macOS `getpeereid` reports kernel-established effective peer UID/GID at socket connection. This supports process identity checks, not human-presence verification; another process with the same effective UID satisfies that identity. The reference is archived and target behavior still requires a spike. [Apple getpeereid manual](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man3/getpeereid.3.html)
8. OAuth device authorization obtains authorization through a browser on another device and involves an authorization server. Selecting device flow alone does not establish the identity provider's MFA policy or transaction approval semantics. [RFC 8628](https://www.rfc-editor.org/rfc/rfc8628.html)

## Options and proposed position

**Owner-only Unix sockets with peer identity** best match the existing single-host MVP, provided generator and evaluator processes really run under different identities. It removes a reusable routine HTTP credential from the local CLI path. This is an inference from the deployment constraints and fact 7, not a source mandate. Socket-directory ownership, startup replacement rules, peer checks, and service identity must all be tested. Same-UID compromise remains outside this protection.

**Loopback bearer authentication** is an acceptable simpler transport candidate, but the token is reusable and loopback is not an identity boundary. A compromised worker must neither inherit nor read it. Storing another unrestricted bearer beside it adds no meaningful protection against that compromise.

**Managed OIDC plus MFA** offers a clearer path to stronger human authentication but introduces identity-provider availability, enrollment, recovery, and issuer/audience validation work. It still needs operation-specific approval. Reserve it for requirements that justify the dependency, or if the local threat model explicitly requires resistance to same-UID malware.

My provisional recommendation is Unix sockets for routine local operations; keep sensitive mutations disabled until the panel chooses and proves a distinct approval mechanism. Proposed approval data binds operation, task, exact candidate SHA, base SHA, reason, expiry, nonce, and deployment audience. Verify against server-held task state and consume atomically with the durable mutation decision. These field choices are project-specific engineering judgments.

The brake should be a separately supervised process with a separate credential and narrow stop-only interface. It must act without the main service, Restate, or Postgres, and must not accept the routine operator credential. Separate credential storage is insufficient if both credentials are exposed to the same compromised principal. This requirement follows existing R9, not an assertion that NIST mandates this watchdog design.

## Proof gaps and bounded spike

No distinct worker identity, independent watchdog, trusted approval display, durable single-use record, or deployed auth configuration is proven. Before mutation routes open, test wrong-peer denial, stolen routine-token denial for approval/brake, expiry, altered SHA/reason/action, concurrent replay, restart replay, and candidate replacement between approval and execution. Use a disposable local service and fake child process; no account creation or live promotion. Stop the main service and database, then demonstrate that the independent brake still terminates the registered child group and cannot target arbitrary PIDs. Record unsupported assertions as blocked, not passed.
