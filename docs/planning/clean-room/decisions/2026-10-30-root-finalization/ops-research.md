# Contrarian operations research — root finalization

Reviewed 2026-10-30. No NUC mutation or implementation was performed.

## Preliminary recommendation

Adopt additive root-attested finalization in the existing exclusive claim object,
but reject the draft's open-ended deferral of the user-visible status path. A
new durable record that leaves every operator command reporting the old leased
state is another partial milestone. Ship finalization together with an additive
read model and CLI status that distinguishes `evaluated_pass`, `evaluated_fail`,
and `unknown`, always showing unknown actual spend honestly. Keep promotion a
separate human action. Do not reopen the reserved worker claim or invent a zero
cost to satisfy the old receipt schema.

Evidence grade: ADEQUATE for choosing the additive boundary; INSUFFICIENT for
production acceptance until the disposable crash/restart and ingress tests pass.

## Evidence and sources

1. Current source makes a launch reservation permanent: `allow_mutation` rejects
   every subsequent worker mutation. `ClaimLeaseJournal.complete` invokes that
   guard before loading the claim. Existing claims cannot safely complete through
   that worker path merely because their lease expired. Primary repository
   sources: `clean-room/crates/control-plane/src/launch_reservation.rs` and
   `workflow.rs` (`ensure_launch_unreserved`, `complete`).
2. The current completion reducer checks a finite, nonnegative numeric spend and
   a live matching lease, then changes successful completion to `Evaluating`.
   The projection also binds that stage to a successful numeric-spend receipt.
   Unknown routed cost cannot be represented as that historical success.
   Sources: `workflow.rs:1585`, `projection.rs:228`, `shared/src/lib.rs:25`.
3. Restate exclusive handlers serialize state mutations per object key; shared
   handlers provide concurrent read access. This supports checking the existing
   reservation and committing finalization in one claim object. Source, read
   live: [Restate handlers](https://docs.restate.dev/foundations/handlers.md).
   The documentation site did not expose a publication date; accessed2026-10-30.
4. A persisted durable-step result is replayed, but an external action can repeat
   if the process fails before its result is durable. Therefore the finalization
   handler should only record already-established evidence, never create Docker
   containers or mutate Git inside a retryable side effect. Primary SDK reference:
   [ObjectContext.run](https://restatedev.github.io/sdk-typescript/interfaces/_restatedev_restate-sdk.ObjectContext#run).
   This explains the general execution model; the installed project pins Rust
   SDK0.12.1 in `clean-room/Cargo.lock`, so exact Rust behavior needs the spike.
5. Restate deployment versioning routes retries to the registered immutable
   endpoint associated with their original version. A mutable endpoint upgrade
   cannot be presumed replay-compatible. Source, read live:
   [Restate versioning](https://docs.restate.dev/services/versioning.md),
   accessed2026-10-30, no displayed publication date.
6. Linux pathname socket permissions and peer credentials are different checks.
   Credentials describe the socket peer at connection/socket creation time;
   they do not prove which service process currently handles an inherited
   systemd listener. Source: [Linux unix(7)](https://man7.org/linux/man-pages/man7/unix.7.html),
   accessed2026-10-30. Require existing post-start process attestation as well as
   UID0 admission; do not promise protection against a compromised root account.

## Options

| Option | Operational benefit | Main cost or failure |
| --- | --- | --- |
| Additive finalization plus a narrow finalization read model/CLI | Preserves old history; makes this run's evaluated outcome visible without falsifying its lease or spend | Adds a second explicit status dimension; all consumers must distinguish it from promotion |
| Change legacy completion and receipt schema immediately | One apparent lifecycle state | Broad replay/projection/budget compatibility migration, plus temptation to weaken the permanent fence |
| Write another root-only JSON receipt and stop | Minimal implementation | Leaves journal and operator UX disconnected; does not complete the stated pipeline |
| Clear the reservation and call worker complete | Reuses old code superficially | Invalidates the one-use boundary, depends on expired lease behavior, and still cannot truthfully encode unknown spend; reject |

The additive option wins only if its read path and recovery are included in the
same acceptance slice. Broad legacy migration can remain a separate task; a
clear finalization summary must not.

## Concrete requirements and inference

The following are recommendations, not facts supplied by Restate:

- Make the root request carry only the fixed generation selector. Resolve every
  evidence path and immutable scope server-side. Record versioned digests and
  the full stored reservation binding, not caller assertions such as
  `exact_cleanup=true`.
- An identical finalization replay returns the original record. A changed
  replay conflicts permanently. A failed/unknown result must never create an
  approval-eligible candidate. Decide explicitly whether unknown is terminal;
  I recommend immutable terminal unknown with a separate append-only recovery
  observation, rather than allowing a hidden overwrite to pass.
- Do not make successful SQL projection a prerequisite for the authoritative
  finalization response. Commit an outbox item with the record, then export
  idempotently; status must identify a pending or quarantined projection.
- The CLI should display `evaluation passed; promotion pending; actual spend
  unknown` for a passing finalization. It must not report production completion
  or human approval. Preserve the old claim snapshot as historical state.
- Finalization of the already reserved generation does not require appending a
  new active generation to the registry. Registry append/restart is required
  before another fresh run. Keep the two protocols separate. The current
  append proposal needs its admission lock, exact restart and fresh process
  attestation implemented; its16-entry limit cannot silently evict history.

## Unknowns and smallest spike

Exact same-object state/outbox atomicity and conflict responses must be tested
against the pinned Rust SDK, not inferred from TypeScript documentation. The
root evidence verifier, private ingress isolation, independent evaluator receipt
and complete projection/reexport path do not yet exist for finalization.

Use disposable Restate/Postgres with old claim/grant history and the additive
handler at a distinct immutable SDK URI. Finalize an expired-but-reserved claim;
drop the response after journal commit; restart SDK and retry the identical
request; assert one immutable finalization and one outbox version. Then change
one digest, attempt worker/direct-ingress bypass, and remove SQL projection
state. Conflicts must remain conflicts; old history and the permanent fence
must remain intact; explicit reexport must reconstruct the same CLI summary
without repeating any Docker, provider, Git or approval effect. Add evaluated
fail and unknown cases before accepting the protocol.
