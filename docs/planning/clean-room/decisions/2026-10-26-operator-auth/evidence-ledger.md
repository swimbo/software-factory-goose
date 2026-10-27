# Authentication evidence ledger

Date: 2026-10-26. Research briefs: `research-appsec.md`, `research-rust-ops.md`, `research-usability.md`.

## Evidence grade

**ADEQUATE** to select and test routine local transport; **INSUFFICIENT** to enable privileged mutation or claim MFA. The debate can recommend a bounded spike and required proof, but must not present a completed human-authorization mechanism.

## Questions and verified facts

| Question | Fact / evidence | Source and date |
|---|---|---|
| Is a new Rust HTTP stack needed? | Pinned Axum 0.8.9, Tokio 1.53.3 and reqwest 0.12.28 support Unix sockets; Tokio obtains macOS peer identity from the kernel. | Installed Cargo.lock/registry sources cited in Rust-ops brief; checked 2026-10-26. Official https://docs.rs/axum/latest/axum/serve/trait.Listener.html and https://docs.rs/tokio/latest/tokio/net/struct.UnixStream.html corroborate APIs. |
| Does UID authenticate a human? | Kernel peer credentials identify the OS principal; same-UID processes are indistinguishable for this purpose. | Apple getpeereid manual (archived, corroborated by pinned Tokio implementation): https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man3/getpeereid.3.html |
| Is a bearer token alone enough? | Bearer authority follows possession; protection, expiry and careful handling remain necessary. | RFC 6750, 2012, controlling protocol reference: https://www.rfc-editor.org/rfc/rfc6750.html |
| What must an approval protect? | Significant action data must be presented; authorization checked at execution; changes invalidate approval; consumption must be unique/atomic and time-bounded. | OWASP, retrieved 2026-10-26, update date unavailable: https://cheatsheetseries.owasp.org/cheatsheets/Transaction_Authorization_Cheat_Sheet.html |
| Do two local tokens establish MFA? | Two readable secrets do not establish distinct authentication factors. | NIST SP 800-63B-4: https://pages.nist.gov/800-63-4/sp800-63b.html#aal2 |
| Does device flow solve transaction approval? | Device authorization provides an external browser interaction, expiry and polling; issuer MFA policy and factory action binding still require design. | RFC 8628, 2019: https://www.rfc-editor.org/rfc/rfc8628.html |
| Is graceful main-service shutdown an independent brake? | No; independence from main-service/DB failure is an existing R9 requirement. | Existing consensus R9 plus pinned Axum shutdown implementation. Engineering inference, not a standards claim. |

## Agreement, contradictions and proof gaps

All three reviewers prefer a peer-checked Unix-socket spike for routine local access over adding bearer-secret lifecycle or an OIDC provider now. This is project-specific judgment. No external source prescribes it.

The apparent tension is between a usable local CLI and strong human-presence proof. Resolve by separating routine peer authentication from transaction authorization. Neither UID nor a confirmation prompt is MFA. A later device/identity mechanism remains unselected.

The upstream Axum example removes a preexisting socket unconditionally and unwraps peer credentials; it is API evidence, not a production lifecycle template. The spike must reject unsafe preexisting paths and credential-read failures.

Missing proof: distinct deployed UIDs, trusted approval channel, atomic durable nonce consumption across restart, candidate/base binding at merge, and a separately supervised stop-only watchdog that rejects ordinary credentials and arbitrary PID targets. Synthetic peer mismatch tests do not prove deployed UID isolation.

## Spike boundary for position papers

Recommend or contest an isolated temporary-directory Unix socket prototype with expected-UID checks, safe bind/restart refusal, owner-only directory/socket modes, and reqwest client. Do not enable runtime mutation. Follow with transaction/independent-brake proofs only after a concrete human-authorization mechanism is selected. Keep privileged endpoints unavailable while these gates are unmet.
