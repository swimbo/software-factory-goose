# Root finalization evidence ledger

Reviewed2026-10-30. Three reviewers approved by the user: durable systems,
application security and contrarian operations. Research is in
durable-research.md, security-research.md and ops-research.md. Evidence is
ADEQUATE for choosing a protocol and INSUFFICIENT for production acceptance.

## Questions

Choose how a permanently reserved generation records a root-attested outcome
after worker shutdown, without reopening worker authority or inventing spend.
Define exact replay, root evidence, operator status and projection recovery.
Keep fresh-generation registry publication and human promotion distinct.

## Verified facts and primary sources

| Fact | Source | Boundary |
| --- | --- | --- |
| Worker mutations are denied after launch reservation, including after lease expiry | `clean-room/crates/control-plane/src/{workflow,launch_reservation}.rs` | Reservation alone does not prove launch or cleanup |
| Root binding includes full reservation and root launch catalog/recipe | `clean-room/crates/watchdog/src/root_grant.rs` | Caller-asserted digest is insufficient |
| Legacy completion requires numeric spend and a live worker lease | workflow.rs, projection.rs, shared/src/lib.rs | Unknown cost cannot become zero or legacy completion |
| Exclusive handlers serialize per object/key; shared reads may run concurrently | [Restate handlers](https://docs.restate.dev/foundations/handlers), [services](https://docs.restate.dev/foundations/services) | Test one-envelope visibility on pinned SDK0.12.1/server |
| Durable replay does not establish physically once-only external effects | [Durable steps](https://docs.restate.dev/develop/ts/durable-steps), [actions](https://docs.restate.dev/foundations/actions) | Root cleanup must precede finalization; SQL delivery needs idempotency/conflict checks |
| Registered deployment version and immutable endpoint matter for replay | [Restate versioning](https://docs.restate.dev/services/versioning) | Do not force-register a changed live endpoint |
| Socket peer credentials do not identify the current inherited-listener server process | [Linux unix(7)](https://man7.org/linux/man-pages/man7/unix.7.html) and existing root attestor source | Require accepted UID0 plus protected post-start process/endpoint attestation |

External pages were accessed by the reviewers on2026-10-30; no displayed
publication date was established. Current TypeScript examples explain general
semantics and do not prove pinned Rust behavior. Repository source is primary
for this implementation.

## Shared recommendation and resolved details

All reviewers prefer additive same-object root finalization over clearing the
fence, direct SQL authority or changing worker completion. Durable systems
requires the finalization and pending outbox item in one versioned state
envelope. Security requires immutable fixed-path evidence, full recomputed
binding and private-ingress bypass controls. Operations requires an additive
read model and CLI in the same acceptance slice; another invisible durable
record is not sufficient delivery.

All three reviewers agreed after positions and one targeted round:

1. Include authoritative CLI status/read model and idempotent SQL reexport in
   the initial slice; preserve the historical legacy claim separately. Store
   decision and pending outbox event in one bounded versioned state envelope.
2. Authenticated, fully bound root uncertainty may be immutable terminal unknown
   with separate append-only recovery observations. Unauthenticated/unbound
   observations remain unfinalized. Neither may become pass through changed
   replay, and recovery cannot silently reopen execution or eligibility.
3. Validate immutable root inputs before commit and compare complete reservation
   plus recomputed catalog/recipe binding in the same exclusive object. Pass
   requires committed blob equality. Failure requires exact snapshot/evaluator
   failure/shutdown but commit is optional and, if present, must match. Unknown
   may omit unavailable evidence while explicitly identifying uncertainty.
4. Pending SQL alone need not block eligibility if the adapter validates the
   authoritative immutable pass and exact identities. Known integrity conflict
   quarantines advancement; stale SQL or unavailable authority cannot authorize.
   Bind eligibility to checked decision/version and prevent a cached clean view
   from bypassing a known conflict. Human action-bound approval remains separate.
5. Registry append is needed before another fresh generation, not finalization
   of an existing reservation. No implicit handler upgrade, force registration,
   host reboot or history eviction follows from this choice.

**CONSENSUS_REACHED.** The exact adopted protocol and acceptance sequence are in
[consensus-plan.md](consensus-plan.md); durable-round1.md, security-round1.md and
ops-round1.md independently confirm the two final disputed details. No major
protocol disagreement remains. This is design consensus, not implementation or
production acceptance, and no new human trust choice was manufactured.

## Acceptance proof still required

Disposable pinned Restate/Postgres tests: expired reservation, full binding
substitution, forged peer/direct ingress, missing or mutable evidence, concurrent
and changed replay, journal commit/lost reply/restart, SQL commit/lost reply,
projection deletion/reexport/conflict, all earlier catalog histories readable,
and continued worker mutation denial. No Docker/provider/Git/approval effect
belongs inside this retryable handler. A new record never itself grants human
promotion approval.

Also prove variant evidence and optional failure commit rejection, authoritative
CLI availability while SQL is pending, authoritative quarantine propagation and
the conflict/admission race, and exact-evidence eligibility with separate human
approval. Actual immutable evidence producers and independent evaluator authority
remain host integration blockers; current docs and mocked journal tests cannot
establish them. Fresh-generation registry admission is a separate open gate.

## Native authorization evidence

The [native synthetic authorization canary](../../verification/2026-10-30-nuc-root-authorization-canary.md) passed with UID 0 publication, UID 2000 exact read and denial controls, UID 2001 lock denial, and a publisher kill after file fsync before directory fsync. Its pending marker remained and the reader denied the interrupted publication. Exact source, binary hashes and retained bridge receipts are recorded there. This establishes only the filesystem/identity fixture: the earlier [disposable journal results](../../verification/2026-10-30-root-finalization-disposable.md) preceded mandatory authorization and do not prove direct journal denial, authorized replay or restart under the new gate. Those checks remain required with a real UID 2000 SDK and root publisher.

The subsequent [authorized disposable journal fixture](../../verification/2026-10-30-authorized-journal-fixture.md) exercised the mandatory reader under UID 2000: direct unpublished delivery returned 403, exact root-published delivery succeeded, changed delivery returned 403, and identical replay survived owned SDK/Restate restart. It remains a synthetic restate-only fixture without production registry admission; the trust and lost-ack limits are recorded in the receipt.
