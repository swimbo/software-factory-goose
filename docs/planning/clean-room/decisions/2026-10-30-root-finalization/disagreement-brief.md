# Moderator disagreement brief — round 1

Reviewed2026-10-30 from the three research briefs, position papers and shared
[evidence ledger](evidence-ledger.md). No NUC action was performed.

The major protocol decisions converge. Evidence is **ADEQUATE for the design
choice**, **INSUFFICIENT for production acceptance**. Two narrow details need
explicit confirmation before the final consensus contract; neither justifies
reopening the selected boundary.

## Resolved

| Decision | Consensus and evidence |
| --- | --- |
| Authority | Additive root finalization in the same exclusive claim object; retain the permanent reservation and legacy state. Full reservation and root catalog/recipe binding must be recomputed and compared. All three positions agree; see [durable](durable-position.md), [security](security-position.md), [operations](ops-position.md), and the repository sources linked there. |
| State and outbox | One bounded versioned envelope contains immutable finalization and pending outbox event. SQL is an idempotent, conflict-detecting derived view. No claim of atomic external Docker/SQL effects. [Restate handlers](https://docs.restate.dev/foundations/handlers) and [durable steps](https://docs.restate.dev/develop/ts/durable-steps) support the model; pinned SDK0.12.1 tests remain required. |
| Visible delivery | The initial slice includes authenticated authoritative CLI/read model and explicit SQL reexport. Authority unavailable is unavailable; stale/absent SQL cannot imply absence or pass. Legacy claim state is separately labeled historical. All reviewers explicitly accept this condition. |
| Unknown versus unfinalized | Authenticated, full-binding root uncertainty may be an immutable terminal unknown. If caller, binding or immutable observation cannot be authenticated, leave unfinalized. Changed replay conflicts; recovery observations append separately and never rewrite unknown into pass or reopen execution. All reviewers explicitly concede this distinction. |
| Evidence variants | Pass requires exact snapshot, independent evaluator receipt, committed blob equality, verified shutdown and exact-ID reconciliation. Failure needs an authenticated evaluator failure and exact snapshot/shutdown. Unknown may omit unavailable cleanup/evaluator/candidate evidence and must identify that uncertainty without success-shaped defaults. See narrow question1 below. |
| Ingress | Accepted UID0 before bounded body read, protected server process/endpoint attestation and direct-Restate bypass denial. Socket credentials alone do not identify the current inherited-listener program. [Linux unix(7)](https://man7.org/linux/man-pages/man7/unix.7.html). Root/daemon compromise remains outside the stated trust boundary. |
| Spend and effects | Unknown actual spend remains explicit; never create zero or legacy completion. Finalization handler does not launch, clean up, invoke models, mutate Git or approve. All three positions agree. |
| Registry | Finalizing an existing reservation does not require a new registry entry. Fresh-generation append/restart is separate, preserves history, and needs its own admission/attestation/replay gates. No force registration, eviction or new generation follows from finalization. [Restate versioning](https://docs.restate.dev/services/versioning). |
| Promotion | An additive eligibility adapter must compare immutable evaluated-pass identity with exact generation/candidate/baseline/evaluation evidence and retain separate human action-bound approval. Unknown/fail/unfinalized do not qualify. This is required before full pipeline completion, rather than evidence that finalization alone finishes the factory. Operations states this explicitly; security and durable positions prohibit automatic promotion. |

## Targeted round-1 confirmations

1. **Failure commit identity — durable reviewer primarily, others confirm.**
   The durable position says both evaluated outcomes bind evaluated commit/blob
   identity. Security and operations explicitly allow evaluated-fail without a
   successful candidate commit. Proposed resolution: failure always requires an
   immutable exact snapshot and authenticated evaluation failure; commit identity
   is optional for failure, and if present must match those exact bytes. Pass
   always requires committed blob equality. No successful commit or passing
   metrics can be mandatory evidence for a failed evaluation. Maintain or concede?

2. **Projection state versus eligibility — all reviewers.**
   Authoritative finalization must be visible while SQL is pending, but the
   positions do not explicitly resolve whether pending SQL blocks promotion
   eligibility. Proposed resolution: SQL delivery is not outcome authority;
   eligibility must read and validate the authoritative immutable pass, while
   any known projection integrity conflict quarantines downstream advancement
   until reconciled. Pending SQL alone must never be called promotion approval
   or whole-pipeline completion. Confirm whether pending SQL may be eligible
   under this authoritative check, or require a stricter current-projection
   gate and explain why. No decision here may permit stale SQL to authorize.

These are implementation-contract confirmations, not additional human trust
choices. If reviewers explicitly agree, the moderator can record
`CONSENSUS_REACHED`; otherwise record the remaining disagreement without
manufacturing consensus.

## Proof gaps remain blockers

Actual root evidence producers, independent evaluator authority, immutable input
validation, authenticated ingress/process identity and old-history compatibility
must be demonstrated. Disposable pinned Restate/Postgres tests must cover full
binding substitution, expiry, wrong peer/direct ingress, equal/changed/concurrent
replay, journal commit/lost reply/restart, SQL commit/lost reply, projection
deletion/reexport/conflict, variant evidence rejection and continuing worker
mutation denial. The single-envelope visibility and crash behavior are not
proved by current TypeScript documentation. A tested eligibility adapter and
separate human approval remain necessary before connected INT-LOOP completion.
