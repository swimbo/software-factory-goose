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

## Shared recommendation and contested details

All reviewers prefer additive same-object root finalization over clearing the
fence, direct SQL authority or changing worker completion. Durable systems
requires the finalization and pending outbox item in one versioned state
envelope. Security requires immutable fixed-path evidence, full recomputed
binding and private-ingress bypass controls. Operations requires an additive
read model and CLI in the same acceptance slice; another invisible durable
record is not sufficient delivery.

Resolve in positions/round1:

1. Must the initial slice include authoritative CLI status and idempotent SQL
   reexport? Proposed yes; preserve the historical legacy claim separately.
2. Is unknown an immutable terminal result with separate append-only recovery
   observations, or should uncertain attempts remain unfinalized? Neither may
   become pass/approval through a changed replay.
3. Exact evidence envelope and root binding: validate immutable inputs before
   commit; compare canonical full reservation and root catalog in the same
   exclusive object. Define which failed/unknown fields may be absent.
4. Registry append is needed before another fresh generation, but not to record
   an existing reserved generation's finalization. No implicit handler upgrade,
   force registration, host reboot or history eviction follows from this choice.

## Acceptance proof still required

Disposable pinned Restate/Postgres tests: expired reservation, full binding
substitution, forged peer/direct ingress, missing or mutable evidence, concurrent
and changed replay, journal commit/lost reply/restart, SQL commit/lost reply,
projection deletion/reexport/conflict, all earlier catalog histories readable,
and continued worker mutation denial. No Docker/provider/Git/approval effect
belongs inside this retryable handler. A new record never itself grants human
promotion approval.
