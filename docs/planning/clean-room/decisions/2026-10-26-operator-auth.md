# Operator authentication and independent brake

Status: three-reviewer, one-round debate complete on 2026-10-26. Consensus selects an inert Unix-socket verification spike only. After the debate, the user selected O4: "Separate local operator account and action-bound approval channel; no MFA claim". Mechanism selection is resolved by that instruction. Privileged activation, deployed identity isolation, durable approval consumption and independent brake remain unverified. See [bounded consensus](2026-10-26-operator-auth/consensus-plan.md), [evidence ledger](2026-10-26-operator-auth/evidence-ledger.md), and [debate transcript](2026-10-26-operator-auth/debate-transcript.md).

## Problem and constraints

The single-operator macOS factory exposes unauthenticated mutating HTTP routes on all interfaces. Promotion can currently mark a task complete without a verified receipt. Budget and stop endpoints report success without performing their actions. Consensus R2/R9/O4 requires human promotion authority, an independent out-of-band brake, and an operator authentication decision before usable approval gates. Root is removing false-success behavior separately from this decision.

Target verified this session: ba-2.local, Darwin, operator uid 501. Goose exists but the planned flags are unsupported. No generator/evaluator identities or Bifrost configuration are present in this process environment. Runtime provisioning is not inferred from library tests.

## Questions

1. Which authentication mechanism should the CLI use for a single-host MVP?
2. How are approval operations bound to exact task, candidate SHA, reason, expiry, and one-time authorization without confusing two stored tokens with MFA?
3. How does the emergency brake remain independent of compromised operator credentials and main-service availability?
4. Which proof must precede enabling mutation routes?

## Options

- Loopback bearer token for routine operations, separately provisioned step-up authorization for promotions/budget/credentials. Simpler CLI transport; shared-machine malware and secret storage must be addressed.
- Owner-only Unix sockets with peer UID checks for operator operations, plus independent watchdog/socket and transaction-bound approval. Requires distinct worker identity and safe socket lifecycle; UID alone is not MFA.
- OIDC/device flow with a managed identity provider and MFA. Stronger identity integration but adds an external dependency and setup beyond the present local MVP.

## Reviewers and research

Application security, Rust operations, and contrarian usability. Each researches primary sources, then positions are compared against a shared evidence ledger. No new authentication architecture is adopted before synthesis.

Initial references (retrieved 2026-10-26):
- https://cheatsheetseries.owasp.org/Transaction_Authorization_Cheat_Sheet.html
- https://cheatsheetseries.owasp.org/Authorization_Cheat_Sheet.html
- https://docs.rs/tokio/latest/tokio/net/struct.UnixStream.html
- https://github.com/tokio-rs/axum/blob/main/examples/unix-domain-socket/src/main.rs

Research and debate artifacts belong in `decisions/2026-10-26-operator-auth/`; existing architecture consensus must not be overwritten.

## Post-debate user selection

The user selected **Separate local operator account and action-bound approval channel; no MFA claim**. This resolves the mechanism choice left open by the debate. Implement the pure action-bound contract and a feature-gated Restate journal adapter, but do not infer live authorization from a configured UID. A private kernel-authenticated adapter must establish request authority; the journal must not be registered on generally reachable ingress before that boundary is proven. Activation still requires actual distinct identities, authoritative task/evidence eligibility, durable nonce consumption and independent-brake proof.
