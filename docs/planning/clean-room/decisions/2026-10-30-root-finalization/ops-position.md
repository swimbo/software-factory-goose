# Operations position: finalize a visible outcome, not another partial milestone

## Recommendation and assessment

Choose additive root finalization in the same exclusive claim object, delivered
with authoritative operator status and recoverable SQL projection. Preserve the
permanent reservation and represent unknown spend explicitly. I maintain this
choice over both reopening worker completion and a broad legacy receipt
migration. Evidence is ADEQUATE for choosing that direction and INSUFFICIENT
for production acceptance, as the [shared ledger](evidence-ledger.md) states.

The revised protocol is sound as a bounded completion record. It is not yet a
complete software-factory pipeline. The practical risk is that we build another
excellent isolated authority and leave the user unable to see or act on its
result. Security and durable systems have accepted my first objection: status
and projection recovery belong in this slice. My remaining hard stance is that
we identify the next narrow connection to approval eligibility before calling
this integration finished. Finalization is allowed to be a necessary component;
it must not be presented as the whole delivery.

## Visible status and SQL recovery: maintain

I maintain that the first acceptance slice includes an authenticated CLI read
from the authoritative journal, plus SQL delivery and explicit reexport. The
operator should receive a concise result such as `evaluation passed; promotion
pending; actual spend unknown`, with the evidence identity available. If SQL is
unavailable, that must not conceal an already committed decision. If authority
cannot be read, the command must report unavailable rather than consult stale
SQL and guess. Legacy claim state can remain visible as historical context; it
must not be the only status a user sees after root finalization.

I concede the durable reviewer's specific implementation recommendation: use a
single bounded versioned envelope for the immutable decision and pending outbox
item. That is a simpler operator recovery boundary than independent state keys
whose externally visible intermediate states have not been proved. Restate's
documented exclusive handler semantics support one writer per object key,
while shared readers need a coherent value to interpret. The exact behavior
must be tested on the project's pinned Rust SDK0.12.1. [Restate handlers](https://docs.restate.dev/foundations/handlers),
[durable position](durable-position.md).

SQL is a reconstructible view, not a second authority. Use stable event
identity and insert-or-compare semantics; a duplicate with different payload is
an integrity conflict, never an update that makes a dashboard look current.
Explicit reexport after projection deletion must reconstruct the same visible
summary without repeating container, provider, Git or approval actions. I
concede that journal finalization must not wait for SQL success. Its initial
reply may truthfully say projection pending. Restate replay does not remove
the need for external-system idempotency. [Evidence ledger](evidence-ledger.md),
[Restate durable execution reference](https://restatedev.github.io/sdk-typescript/interfaces/_restatedev_restate-sdk.ObjectContext#run).

## Unknown versus no finalization: maintain with a qualification

I maintain immutable terminal `unknown` for an authenticated, reservation-bound
root observation that cannot establish the execution outcome. This gives a
real operator something actionable: the exact generation, known phase,
bounded uncertainty and retained evidence identity. Leaving every uncertain
attempt indistinguishably unfinalized is safe but operationally inadequate.
It encourages ad hoc inspection and repeated questions about whether a run
can be restarted.

I concede security's qualification: if the caller, reservation, profile binding
or immutable observation cannot be authenticated, no accepted finalization is
justified. The status remains unfinalized. `Unknown` is not a substitute for
missing authority; it is an authoritative statement about uncertainty.

Identical replay returns the original record; changed replay conflicts. Later
recovery may append a separate observation saying, for example, that exact-ID
cleanup was established. It must not overwrite unknown with pass, imply a new
lease, or silently make the candidate approval eligible. I accept that a later
adjudication transition would require its own reviewed contract. The CLI should
show that later cleanup observation alongside the unchanged original outcome,
so immutability does not hide useful recovery progress. [Security position](security-position.md),
[durable position](durable-position.md).

## Typed evidence: concede stronger requirements, reject uniform success fields

I concede the reviewers' full reservation/profile binding requirements. The
server resolves evidence paths from protected catalog state; the root peer does
not submit arbitrary paths, hashes or task claims. Accepted UID0 credentials
and protected post-start service attestation are both required. Linux peer
credentials alone do not identify the current program serving an inherited
listener. This is a trusted-root design and must not claim resistance to root
compromise. [Linux unix(7)](https://man7.org/linux/man-pages/man7/unix.7.html),
[root adapter](../../../../../clean-room/crates/control-plane/src/root_launch_grant.rs).

I maintain that each result variant needs its own mandatory evidence rather
than one success-shaped structure full of optional booleans. Pass requires
exact immutable candidate bytes, independent evaluator provenance and result,
committed blob equality, verified closure and same-inode frozen-empty cgroup,
terminal producers and exact container absence. Evaluated failure requires an
authenticated evaluator failure bound to an exact snapshot and verified
shutdown; it cannot require a passing result or successful candidate commit.
Unknown needs authenticated reservation/profile identity and an immutable
bounded observation identifying established versus unresolved facts. Missing
cleanup in unknown is not `cleanup=false` and certainly not `cleanup=true`.
No result may synthesize numeric spend. The current legacy receipt's numeric
contract is why the additive route is useful. [Workflow completion reducer](../../../../../clean-room/crates/control-plane/src/workflow.rs),
[projection](../../../../../clean-room/crates/control-plane/src/projection.rs).

## Full-pipeline integration and registry scope

I maintain that additive status alone does not enable the full pipeline. The
next narrow integration must let promotion eligibility consume an immutable
`evaluated_pass` record whose generation, candidate, baseline and evaluation
digests match its request, and then require the already separate human
action-bound approval. Unknown, evaluated fail, unfinalized, pending evidence
and conflicting projection must never become eligible. This is an additive
eligibility adapter, not a rewrite of historical worker completion or an
automatic promotion. It needs end-to-end tests from finalization through
eligibility refusal/acceptance and human approval replay protection before the
full INT-LOOP can be called complete.

I concede and maintain the consensus that registry append is separate.
Finalizing a retained reserved generation must not depend on creating another
one. Fresh-generation admission does need the separate append/restart protocol,
its shared admission lock, historical retention and new process attestation.
Do not bundle force registration, service migration, history eviction or a new
generation into the finalization handler. Immutable deployment compatibility
remains a real release constraint. [Registry proposal](../2026-10-29-nuc-root-supervisor/registry-append-protocol.md),
[Restate versioning](https://docs.restate.dev/services/versioning).

Before acceptance, demonstrate the disposable lost-acknowledgment, restart,
equal/conflicting concurrent replay, wrong peer/direct ingress, substituted
binding/evidence, projection deletion/reexport and worker-mutation-denial cases
listed in the ledger. Demonstrate actual evidence producers separately. My
nonnegotiable items are honest visible state, no fence reset or fabricated
spend, and a tested explicit connection from passing finalization to separately
approved promotion eligibility.
