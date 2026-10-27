# Journal-owned claim history and SQL-loss recovery — 2026-10-27

Result: the bounded claim recovery boundary passed against real disposable Restate and PostgreSQL. This is not full factory data recovery or a production activation result.

## Implementation

`ClaimLeaseJournal` now retains `claim_event_history_v1` in Restate. Every real transition preserves its original `(invocation_id, step_seq)` and typed versioned claim read-model snapshot. The exclusive handler records history and state before its journal-retried SQL delivery. Completed delivery runs do not need to execute again for recovery.

The retained chain is limited to **128 events and 512 KiB serialized history**. Mutations validate contiguous versions, unique event identities, immutable package/base-revision binding and exact equality with the typed projection of the latest authoritative state. Capacity or byte exhaustion fails before changing durable claim state or writing SQL; nothing is silently evicted. The retained event contains only structured read-model fields; the full receipt remains in authoritative Restate claim state. Status remains a stored snapshot, not a fresh lease-validity assertion; retention exhaustion does not authorize reassignment.

Existing nonempty claim state with missing history fails closed. No fabricated initial event, migration from SQL, old-history backfill, compaction or archival protocol is implemented. New journal operations also change handler replay structure: deployment migration for an in-flight old handler is unverified and must not be assumed safe.

The new exclusive `reexport_claim_history` handler takes no caller-selected database, events or identities. It validates the retained source and executes a **fresh** journaled SQL transaction against the configured pool. The transaction inserts the original events and reconstructs the latest claim projection. Exact duplicate delivery is idempotent; unexpected events, conflicting content or a different latest snapshot fail the whole transaction. Normal delivery and re-export share a per-aggregate advisory transaction lock. Other aggregates are untouched.

Deterministic SQL integrity conflicts are terminal and quarantine further claim mutations. Transient DB errors retain the existing journal retry behavior. Successful re-export reports whether quarantine remains; it never clears quarantine or silently resumes execution. A separate reviewed repair/resumption protocol is still absent.

## Real verification

Command sequence from repository root:

```sh
cargo test --locked --manifest-path clean-room/Cargo.toml -p control-plane --all-features --lib
cargo build --locked --manifest-path clean-room/Cargo.toml -p control-plane --all-features --example claim_recovery_fixture --example verify_projection
python3 clean-room/tests/fixtures/claim_projection_recovery.py
cargo clippy --locked --manifest-path clean-room/Cargo.toml -p control-plane --all-features --lib --example claim_recovery_fixture -- -D warnings
```

- Test-first RED recorded missing retained-history APIs. Focused lease tests passed after implementation; the current all-feature control-plane library run passed **140 tests**, zero failures/ignored.
- Runtime: **Restate server 1.8.0**, locked **SDK 0.12.1**, local **PostgreSQL 17.9** and **pgvector 0.8.2**. The fixture is a new disposable cluster with synthetic trust authentication, random loopback ports and its own temporary directories.
- Initialize, claim and completion created three distinct original event keys. The private authoritative state retained the lease token and full synthetic receipt, while serialized SQL events contained neither the token nor raw text. The fixture stopped its SDK, dropped the entire owned `sfactory_verification` database, recreated it empty, and restarted the SDK to run all migrations. Both outbox and claim projection were confirmed empty.
- After forcibly stopping and restarting only its Restate server with SIGKILL, authoritative claim status remained identical. Explicit re-export restored **all original keys and payloads**, plus the exact latest typed projection. A second fresh invocation and another after graceful restart retained the same three rows.
- Injected conflicting version-three SQL data while deleting earlier SQL events. Recovery returned terminal failure, rolled back attempted earlier reinsertions and left the projection empty. After removing that fixture corruption, re-export restored the original history but reported quarantine; a completion mutation still returned 503. Recovery did not authorize resumption.
- A separate claim reached 128 real journaled transitions. The next renewal returned 409, with authoritative state unchanged and exactly 128 retained SQL events. The first fixture version used a maximal lease, so its renewals correctly did not change state; its cap test was corrected to extend a shorter lease before recording this successful result.
- Strict scoped Clippy, rustfmt and diff checks passed. [Machine-readable result](2026-10-27-claim-history-recovery.json).

Only fixture-owned Restate, SDK and Postgres children were terminated; their temporary cluster/journal/socket files were removed. No existing database, container, service, credentials or model invocation was used or changed. The fixture registration is loopback-only and deliberately lacks production authentication proof.

## Recovery contract and remaining gaps

Recovery must enumerate **known claim object keys** from an independently retained inventory; no durable global key inventory/scanner is supplied here. Each SQL-loss recovery cycle requires a fresh handler invocation. Reusing a completed invocation/idempotency key after a second loss can replay its completed `ctx.run` result instead of repeating SQL effects.

Only claim transition events and claim projections are covered. Qualifier, audit, receipt, memory, other aggregates and full factory recovery are not reconstructed by this handler. Losing the Restate journal/state as well as SQL is outside this proof. No crash injection between individual history/state journal writes, disaster failover, old-handler protocol migration, quarantine release, private ingress authorization or deployment registration has been verified. Main production routing remains unchanged and unregistered.

## Security correction after review

The initial implementation serialized the full authoritative claim into SQL. Review identified that this exposed lease fencing tokens and unscanned receipt content. The corrected `schema_version: 2` projection uses explicit typed fields and omits tokens, worker/repository free text, raw diff and stderr. `project_receipt` separately withholds raw diff/stderr and clears the legacy `diff` column for the redelivered key. Unsafe legacy claim payloads are rejected by delivery, re-export and SQL rebuild, not silently copied. Existing persisted unsafe data is not globally purged by this code change; that requires an explicit migration/rebuild plan. Details and canary evidence: [safe projection verification](2026-10-27-safe-claim-projection.md).
