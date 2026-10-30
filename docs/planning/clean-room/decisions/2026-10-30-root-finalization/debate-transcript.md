# Root finalization debate record

**Result: CONSENSUS_REACHED — 2026-10-30.** This is a referenced process record,
not invented verbatim dialogue. No NUC mutation or production test was performed
by this debate. The user approved three reviewers: durable systems, application
security and contrarian operations.

## Research

The supplied [contract draft](contract-draft.md) proposed additive root-only
finalization after permanent reservation, with unknown spend preserved.

- [Durable research](durable-research.md) examined same-object exclusivity,
  journal/SQL replay, full root binding and immutable deployment compatibility.
  It recommended one versioned finalization/outbox envelope and pinned-stack
  tests rather than claiming external atomicity.
- [Security research](security-research.md) examined fixed UID0 ingress, inherited
  listener process identity, private backend bypass, root evidence provenance
  and numeric legacy spend incompatibility.
- [Operations research](ops-research.md) challenged a hidden durable record with
  no reachable user outcome. It required CLI/read model and SQL reexport in the
  initial slice, distinct unknown/unfinalized state and permanent fences.

The parent synthesized the [evidence ledger](evidence-ledger.md), grading the
choice adequate but production proof insufficient. External citations are
primary Restate/Linux documentation; current TypeScript examples were explicitly
not treated as proof of the pinned Rust SDK0.12.1 implementation.

## Positions and moderator synthesis

[Durable position](durable-position.md), [security position](security-position.md)
and [operations position](ops-position.md) converged on the additive same-object
boundary, permanent reservation, single envelope, honest unknown spend,
authoritative status, idempotent export/reexport, fixed root ingress and separate
registry/approval boundaries. Operations also required the narrow promotion
eligibility connection before full pipeline completion.

The neutral moderator wrote [disagreement-brief.md](disagreement-brief.md).
It found major convergence and asked only two targeted round1 confirmations:
whether failure requires a successful Git commit, and whether pending SQL blocks
eligibility supplied by authoritative evidence. It retained the complete set
of runtime proof gaps instead of declaring production ready.

## Round 1

- [Durable round1](durable-round1.md) withdrew its earlier requirement for a
  failure commit. It agreed failure needs exact immutable snapshot, evaluator
  failure and shutdown; an optional commit must match. It accepted pending SQL
  eligibility only through authoritative exact evidence, with known conflicts
  quarantining advancement.
- [Security round1](security-round1.md) confirmed optional failure commit and
  explicitly conceded that ordinary SQL pending need not block authoritative
  eligibility. It retained full binding, unavailable-authority refusal,
  immutable unknown and separate human approval.
- [Operations round1](ops-round1.md) agreed to both resolutions and distinguished
  SQL delivery lag from missing evaluation evidence. It required authoritative
  quarantine/version checks so stale cached status cannot race a known conflict.

All three independently agreed. No second or third round was necessary and no
major contested decision remained. The moderator produced
[consensus-plan.md](consensus-plan.md), resolving the draft's uniform evidence
requirements and open-ended visibility deferral while preserving its trust
boundary. The evidence ledger was updated to record resolved decisions and
remaining acceptance gates.

## Remaining proof and scope

The debate recommends implementation and disposable verification; it provides
no finalizer, evaluator, production ingress, SQL projection, eligibility or
host-recovery receipt. Exact evidence producers, pinned journal/SQL crash and
replay, private ingress refusal, old-history compatibility, visible status,
reexport and conflict/admission behavior must pass. Registry append is separate
and required before a fresh generation. No fence reset, silent history eviction,
force registration, model call, automatic approval or production completion
follows from this consensus.
