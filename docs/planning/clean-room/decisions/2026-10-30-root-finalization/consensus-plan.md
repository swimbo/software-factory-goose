# Root-attested finalization — consensus plan

**CONSENSUS_REACHED — 2026-10-30.** Three approved reviewers completed research,
positions and one targeted round. Evidence is adequate to select this protocol;
actual production acceptance remains blocked on the proof gates below. This
supersedes the conflicting details in contract-draft.md and earlier positions.

## Exact authorization amendment

The same three reviewers conditionally supported protected exact-payload Root
authorization in their `*-authorization-amendment.md` reviews. Namespace
membership is insufficient. Root validates the fixed evidence before publishing
a create-only authorization for the canonical request digest; the SDK requires
that exact authorization in a durable read step before its exclusive decision.
Publication authorizes identical delivery immediately and never promotion.

The identified lock-release crash window is fenced by a pending record synced
before authorization becomes visible. Under the exclusive lock, publish and sync
authorization, publish and sync completion, then unlink pending and sync its
parent last. Readers take a shared nonblocking lock and deny any pending marker,
missing record, unsafe metadata or mismatch terminally. No automatic recovery,
overwrite or reuse follows an ambiguous publication. Actual native Root/UID2000/
UID2001 canaries passed, including SIGKILL after authorization-file fsync and
before parent fsync. Pinned journal ingress/replay tests remain a separate gate.

## Chosen boundary

Add root finalization to the **same exclusive ClaimLeaseJournal object/key** that
owns the permanent launch reservation. Preserve the reservation, historical
claim state and legacy receipt/projection semantics. Do not call worker complete,
clear the fence, revive an expired lease, invent numeric spend or infer approval.

Deliver the authoritative operator status and idempotent SQL projection/reexport
with this slice. An invisible journal record is not sufficient acceptance.
Full pipeline completion additionally requires the exact-evidence eligibility
adapter and separate human action-bound approval. Finalization alone does not
finish the factory.

## Fixed authority and binding

1. A root-only fixed-generation Unix ingress authenticates the accepted kernel
   UID0 **before** reading a bounded request. The request selects only the fixed
   generation; no caller-supplied path, result, candidate, claim proof or evidence
   boolean is authority. Catalog-owned data resolves all paths and scope.
2. A trusted root finalizer validates fixed protected evidence. Check no-follow
   descriptor-relative opens, owners/modes, regular single-link files, ACLs,
   bounds and identities across reads. Root/daemon compromise is outside this
   trust boundary. Independently attest the serving process and endpoint after
   startup; inherited socket peer credentials alone do not establish that
   process. Deny direct untrusted access to the private Restate handler.
3. In the exclusive object, compare the **full stored reservation** and current
   historical claim: task, generation, repository/base revision, worker, attempt,
   token hash, immutable scope and deadline values. Expiry does not invalidate
   a matching retained reservation for historical finalization and never permits
   another claim.
4. Recompute the existing domain-separated root launch binding from the complete
   canonical reservation and exact protected root launch catalog, including its
   recipe digest; validate the recipe bytes. Compare the recomputed binding to
   the verified launch/evidence binding. Caller-asserted digests are insufficient.
   Evidence must remain immutable between root validation and journal recording.

## Versioned record and same-key envelope

Use strict bounded versioned types, reject unknown fields/duplicates/nonfinite
values, and use one deterministic canonical encoding for replay/digest identity.
The initial immutable finalization contains:

- schema version and stable task/generation identity;
- complete reservation identity and root catalog/recipe/full binding identity;
- one tagged outcome described below;
- versioned root observation/evidence identity and actual evidence digests;
- actual spend explicitly unknown where no exact amount was established.

Store **one state envelope** under one versioned claim-object state key. It
contains the immutable finalization and one pending outbox event with stable
identity/version, exact immutable payload and its digest. Export state may later
change pending/current/quarantined through exclusive same-key operations, while
the finalization and original event payload never change. No external SQL,
Docker, provider, Git, cleanup or approval effect is part of deciding/recording
finalization. Do not claim that several separate state writes or a journal step
are atomic with an external system.

Identical canonical finalization replay returns the stored decision. Any changed
reservation, outcome, candidate or evidence conflicts permanently. A changed
export status does not change replay identity of the immutable decision. Bound
all history and observation collections explicitly; capacity exhaustion denies
new writes without deleting old evidence.

## Outcome variants

| Outcome | Mandatory evidence | Consequence |
| --- | --- | --- |
| evaluated_pass | Exact immutable snapshot and content hashes; independently authenticated evaluator pass bound to those bytes; verified committed revision and blob equality; root closure and same-boot/inode frozen-empty cgroup; both exact container IDs reconciled absent; terminal create/start and nonrestartable owned broker/relay jobs | Eligible for exact-evidence eligibility checking, never automatically approved |
| evaluated_fail | Exact immutable snapshot; independently authenticated evaluator failure; same verified shutdown and exact-ID reconciliation. Commit optional; if present its relevant blobs must equal the evaluated snapshot | Ineligible for promotion; no successful commit or passing metrics required |
| unknown | Authenticated fixed root ingress; full reservation/profile binding; immutable bounded root observation identifying established and unresolved facts and phase/reason codes | Immutable terminal uncertainty, always ineligible; unavailable cleanup/evaluator/candidate evidence may be absent and must not default to success |

If caller, binding or immutable observation cannot be authenticated, accept no
finalization: status remains **unfinalized**. Missing evaluator evidence is not
an evaluated failure. Unknown does not assert containment, completion or exact
cost. A later authenticated recovery observation may append a separately typed,
monotonically ordered record linked to the immutable original. It never rewrites
unknown into pass, releases the reservation or silently authorizes advancement.
A later adjudication transition is outside this contract.

## Read model, SQL export and eligibility

Authoritative status reads the claim object's finalization envelope. Show
unfinalized, evaluated pass, evaluated fail, unknown, and authority unavailable
distinctly. Show spend unknown, evidence identity, legacy claim as historical,
and projection pending/current/quarantined separately. A pass reports evaluation
passed with promotion pending; it never reports human approval or deployment.

SQL is reconstructible. Deliver the original durable event using stable event
identity and transactional insert-or-compare semantics: equal key/payload is
idempotent; a differing payload/version under the same identity is an integrity
conflict and must be recorded as authoritative quarantine. Journal finalization
does not wait for SQL success. Explicit reexport redelivers the exact stored
event, including after derived-row deletion; it cannot repeat external execution
or change the finalization. Lost SQL acknowledgment needs destination read-back
and idempotency, not a physical once-only claim.

The narrow promotion-eligibility adapter reads the authoritative immutable pass
and current authoritative quarantine state. It compares exact generation,
baseline, candidate commit/blob identity and evaluation binding, and binds its
result to the checked decision/version. Pending SQL **alone** need not block
this authoritative check. Missing/stale SQL never supplies authority. A known
integrity conflict blocks downstream advancement until reconciled; unavailable
authority or inability to distinguish pending from conflict fails unavailable.
Revalidate the applicable authority/version/quarantine before advancement so a
cached clean view cannot bypass a known conflict. A positive eligibility result
still requires the separate replay-safe human action-bound approval.

## Registry and deployment separation

Finalizing an existing reservation uses its retained catalog and history and
does not require a new registry entry. Fresh-generation admission separately
requires the bounded append/restart protocol, shared admission exclusion,
unchanged historical entries, process/socket attestation and replay proof.
No finalizer may append a generation, force-register an endpoint, evict history
or restart shared services. New handler deployment uses a distinct immutable SDK
URI and preserves old deployments/history; current documentation does not prove
pinned Rust SDK0.12.1 compatibility.

## Implementation and acceptance gates

Implement strict pure types/validation first, then same-object envelope and
authoritative reads; add idempotent SQL sink/reexport and CLI; add authenticated
fixed root transport/evidence verifier and exact-evidence eligibility adapter.
Production activation follows only their concrete reviewed deployment and tests.

Use disposable pinned Restate/Postgres and retained old histories to prove:

1. No reservation; wrong task/generation/spec/worker/attempt/token/deadline;
   altered full catalog/recipe binding; expired-but-reserved finalization.
2. Wrong UID before body read, wrong serving process/socket attestation and
   direct backend bypass refusal; missing/mutable/link/ACL/oversize evidence.
3. Pass/fail/unknown variant requirements, optional failure commit mismatch,
   unfinalized without authority and immutable unknown with later observation.
4. Equal and conflicting concurrent calls, changed replay, loss before/after
   journal commit/acknowledgment, restart, single-envelope visibility and one
   original event identity/version. Worker mutations remain fenced throughout.
5. SQL commit/lost reply, equal delivery/conflict quarantine, derived-row
   deletion/reexport, pending/current/quarantined CLI behavior and unavailable
   authority; no repeated Docker/provider/Git/approval effects.
6. Pending SQL plus authoritative pass eligibility; unknown/fail/unfinalized and
   altered identity refusal; known conflict or unavailable authority refusal;
   conflict/admission race and separately replay-safe human approval.
7. Original, grant-canary, real and registry histories remain readable without
   force registration through the distinct handler deployment.

Separately demonstrate actual root closure, producer termination, exact-ID
reconciliation and independent evaluator/committed-byte evidence. Mocks or green
journal tests do not establish those host facts. Full INT-LOOP, enterprise,
artifact and final human signoff gates remain open until their actual evidence
exists.

## Rationale and sources

This additive boundary preserves existing semantics while exposing honest
completion and recovery. Reusing worker complete/clearing the reservation is
rejected because it weakens one-use authority and cannot encode unknown spend.
Direct SQL authority and separate-object compare are rejected because they
split authority; broad legacy schema migration is deferred.

Primary external semantics: [Restate handlers](https://docs.restate.dev/foundations/handlers),
[durable steps](https://docs.restate.dev/develop/ts/durable-steps),
[versioning](https://docs.restate.dev/services/versioning),
[Linux unix credentials](https://man7.org/linux/man-pages/man7/unix.7.html).
Repository facts and precise citations are in the [evidence ledger](evidence-ledger.md).
The [debate transcript](debate-transcript.md) records the actual review sequence.
