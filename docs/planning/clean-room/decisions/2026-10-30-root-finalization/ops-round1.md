# Operations round 1 — explicit agreement on the remaining details

I agree with both proposed resolutions in the [disagreement brief](disagreement-brief.md).
These settle the remaining contract details without reopening the additive
authority boundary. The evidence remains adequate to choose the protocol and
insufficient to claim production acceptance.

## Failed evaluation does not require a successful commit

I **maintain** that an authenticated failed evaluation can be finalized without
a candidate commit. It must identify an immutable exact snapshot, its content
hashes, the independent evaluator and failing receipt, plus the required
verified shutdown and reconciliation evidence. A commit is optional for this
variant. If one is provided, its blobs must equal the evaluated snapshot; an
unrelated commit cannot strengthen the failure receipt.

Requiring a successful commit for failure adds an unnecessary Git mutation to
the recovery path. The operator needs a trustworthy account of the candidate
that failed, not a new revision manufactured to make the event fit the success
schema. I **concede** any language in my earlier position that could suggest
uncommitted failure evidence is weaker merely because it lacks a Git SHA.
Snapshot identity and evaluator provenance are the material facts. Passing
finalization still requires exact committed blob equality because its next
consumer is candidate promotion eligibility. The project's existing
[completion reducer](../../../../../clean-room/crates/control-plane/src/workflow.rs)
and [projection](../../../../../clean-room/crates/control-plane/src/projection.rs)
show why a new typed variant should preserve this distinction rather than
misusing the historical successful worker receipt.

## Pending SQL may be eligible only through authoritative evidence

I **concede** a stricter interpretation of my earlier statement that pending
evidence must not become eligible: ordinary SQL delivery pending is not missing
evaluation evidence. SQL is a derived view. Pending delivery alone need not
block an eligibility adapter that reads and validates the immutable
authoritative evaluated-pass record and its exact generation, baseline,
candidate and evaluation binding. A missing or stale SQL row must never
authorize that decision or supply missing identity fields.

I **maintain** that a known projection integrity conflict quarantines downstream
advancement until reconciled. A conflicting payload under the same event
identity is materially different from an acknowledged delivery delay. The
adapter must obtain authoritative quarantine state as part of its admission
check, fail unavailable if it cannot do so, and bind any eligibility result to
the checked decision/version. It must not race ahead by consulting a previously
cached clean status after a conflict is known. The exact serialization and
conflict propagation belong in the pinned-stack tests; Restate's per-key
exclusive handlers provide a relevant mechanism, not proof that this new
adapter already implements it. [Restate handlers](https://docs.restate.dev/foundations/handlers),
[durable execution reference](https://restatedev.github.io/sdk-typescript/interfaces/_restatedev_restate-sdk.ObjectContext#run).

## Status and remaining delivery gates

The operator-facing labels remain distinct: unfinalized, evaluated pass,
evaluated fail, immutable unknown, authority unavailable, and projection
pending/current/quarantined. Show unknown actual spend explicitly and preserve
the legacy claim snapshot as historical context. An eligibility check is not
human approval. Promotion continues to require the separate action-bound human
decision tied to the exact candidate and evidence, with replay protection.

I **maintain** that these connections must be tested before declaring the full
INT-LOOP complete. Include wrong identity, altered snapshot, optional-failure
commit mismatch, unavailable authority, pending SQL with authoritative pass,
known projection conflict, lost acknowledgments, restart and explicit reexport.
No test may infer physical once-only Docker or Git effects from durable replay.
Registry append/restart remains a separate future-generation admission
protocol; no force registration or history replacement follows from this
consensus. [Restate versioning](https://docs.restate.dev/services/versioning),
[Linux peer credentials](https://man7.org/linux/man-pages/man7/unix.7.html).
