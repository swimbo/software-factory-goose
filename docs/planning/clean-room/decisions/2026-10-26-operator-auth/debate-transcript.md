# Operator authentication debate record

Date: 2026-10-26. Panel: application security, Rust operations, and contrarian usability. Three research briefs, three position papers, one moderator brief, one response round, and final scoped synthesis. User approval of the panel is recorded in the decision brief. No privileged activation was approved by this debate.

## Research and common evidence

Each persona researched before positioning: [AppSec](research-appsec.md), [Rust operations](research-rust-ops.md), [usability](research-usability.md). The [evidence ledger](evidence-ledger.md) records primary sources: installed Cargo.lock and library implementations; official Axum/Tokio APIs and example; Apple's peer-credential manual; OWASP transaction/authorization guidance; NIST SP 800-63B-4; RFC 6750 and RFC 8628. Source dates and version caveats are retained in the briefs. There are no benchmark or production-readiness claims.

## Initial positions

[AppSec](position-appsec.md) supported an inert socket experiment but rejected interpreting UID, typed confirmation, or two local secrets as strong human authorization. It required explicit denial paths, safe socket lifecycle, and no live factory router.

[Rust operations](position-rust-ops.md) supported the existing pinned networking stack and conservative startup refusal. It separated durable approval consumption and separately supervised watchdog operation from a passing transport test.

[Usability](position-usability.md) favored routine local commands without bearer copying or provider enrollment, while requiring clear capability-specific status instead of an undifferentiated authentication badge.

## Moderator round and responses

The [disagreement brief](disagreement-brief.md) found agreement on the experiment but required precise contracts for client service assurance, cleanup races, and acceptance/availability reporting.

[AppSec round 1](round-1-appsec.md) conceded that direct client-side kernel peer verification may be deferred for an inert harness-owned server in a verified private directory. It also narrowed cleanup claims to controlled replacement and proposed finite experiment/request/body/fixture bounds.

[Rust operations round 1](round-1-rust-ops.md) confirmed pinned reqwest lacks direct peer-credential exposure in its inspected UDS path. It conceded that identity-check followed by unlink is not atomic against hostile same-UID replacement; it specified a controlled replacement test and retained no-unlink startup refusal.

[Usability round 1](round-1-usability.md) accepted those narrower assurance claims and supplied separate verified/synthetic/unavailable reporting. It opposed hidden TCP fallback and any wording that turns synthetic peer denial into deployed isolation.

## Resolutions and final status

| Issue | Status | Resolution |
|---|---|---|
| Routine local transport experiment | RESOLVED | Existing-library Unix socket; inert routes only. |
| Client-side server credentials | RESOLVED for spike only | Directory/socket ownership assurance; actual-connection credential verification explicitly not performed. |
| Cleanup guarantee | RESOLVED for spike only | Preserve controlled replacement; no general race-freedom claim. |
| Resource controls and reporting | RESOLVED | Bounded experiment; separate real/synthetic/not-run/unavailable evidence. |
| Bearer/OIDC selection | DEFERRED | Neither adds necessary capability to this bounded spike. |
| O4 full human authorization | OPEN / INSUFFICIENT | Mechanism unselected; trusted display, intent, transaction binding and durable consumption unproven. |
| Deployed identity separation and brake | OPEN / INSUFFICIENT | Require actual identities and independent watchdog operating evidence. |

**CONSENSUS_REACHED only on the [bounded spike plan](consensus-plan.md).** Evidence is ADEQUATE for selecting/testing local transport, INSUFFICIENT for privileged authority or activation. No second round is needed because the remaining issues are explicitly out-of-scope proof gaps rather than unresolved disagreement about the experiment. Experimental results are recorded separately and do not retroactively expand this decision.

## Subsequent human selection

After the debate concluded, the user selected **Separate local operator account and action-bound approval channel; no MFA claim**. This settles the architectural choice that the panel had left open. It does not convert missing runtime proof into agreement or permit activation. The current implementation scope adds a pure contract and unregistered feature-gated Restate approval adapter; actual adapter/ingress isolation, distinct identities, approval/replay behavior under real Restate, eligibility checks and independent brake still require proof.
