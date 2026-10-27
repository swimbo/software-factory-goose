# Claim journal outbox verification — 2026-10-26

Status: bounded T3/T4 implementation and local SQL integration verified. No runtime activation or live Restate crash/replay claim.

## Implementation boundary

`ClaimLeaseJournal` in `clean-room/crates/control-plane/src/workflow.rs` remains unregistered. Its constructor requires an explicit worker ID and Postgres pool. Configuration is not proof of request identity; an authenticated private worker adapter and trusted scheduler initialization remain required.

Each actual initialize/claim/renew/complete state change increments the authoritative object version and immediately awaits one journaled `ctx.run` delivery. The event identity is `(ctx.invocation_id(), 0)`; aggregate version is separate. Unchanged or duplicate results do not create transitions. A refused request that records lease expiry/cooldown still produces its transition. Mutating handlers enforce time; status returns a stored snapshot and does not assert current lease validity.

`deliver_claim_event` commits immutable outbox event and claim snapshot together. Exact redelivery is idempotent; conflicting event keys or aggregate versions fail. The partial unique index in migration `0003_claim_projection.sql` enforces historical task/version uniqueness, including versions older than the current snapshot. Older valid events cannot move the snapshot backwards. Invalid data, integrity constraints and invalid SQL/schema errors are terminal; transient database errors propagate for Restate retry. Terminal delivery failure preserves the event in `projection_quarantine` and fences subsequent mutations. An explicit repair workflow remains unimplemented.

`rebuild_claim_projection` locks delivery tables, validates retained bindings and duplicate versions, then replaces only the claim projection in one transaction. The SQL outbox is retained. This is reconstruction from retained SQL events, not from the Restate journal. Complete Postgres loss requires a separate journal-backed re-export implementation: completed `ctx.run` effects are not automatically reissued on replay.

## Evidence

Test-first example check failed with unresolved outbox API imports before implementation. Subsequent commands:

- `cargo test --locked -p control-plane --all-features workflow:: --lib`: **14 passed** (8 lease, 2 existing workflow/budget, 4 approval wrapper tests).
- `cargo clippy --locked -p control-plane --all-features --lib --example verify_projection -- -D warnings`: **passed**.
- `cargo test --locked -p control-plane --example verify_projection`: **1 passed**, explicit disposable-loopback URL guard.
- `cargo run --locked -p control-plane --example verify_projection`: **passed**, with explicit `SFACTORY_TEST_DATABASE_URL` targeting each fresh fixture below.
- Scoped `git diff --check`: **passed**.

Final example guard compilation took 2m36s; the database runner waited for Cargo's artifact lock and completed in 2m22s. Neither process was killed. The fixture runner had a 180-second subprocess timeout and unconditional cleanup.

### Disposable database scope

All fixtures used the already-present image `pgvector/pgvector:0.8.2-pg16`, ID `sha256:82da453b7978030817abb8b8bcef55c0e14be243946568668343dc7e811f8d2f`, with `--pull=never`, synthetic trust authentication, database `sfactory_verification`, random numeric loopback published port, no bind mounts, and a unique container name. No standing service was changed.

| Fixture | Container prefix | Loopback port | Result |
|---|---|---|---|
| Prior base projection: `sfactory-verification-9ff0c64df7af` | `df1106a1cd21` | 32768 | Base SQL/pgvector checks passed; own container removed and its exact anonymous volume subsequently identified and removed |
| Initial outbox: `sfactory-verification-0ad43a7ffaef` | `8b5226497a3a` | 32768 | Outbox checks passed; own container and anonymous volume removed together |
| Final regression: `sfactory-verification-41368ba9c348` | `e86c0b3f22ab` | 32769 | All checks below passed; own container and anonymous volume removed together; inspect confirmed container absent |

The reusable harness rejects remote hosts, omitted ports, URL query overrides, credentials, other database names and populated target tables. Its deliberate deletes/schema changes occur only inside the fresh synthetic fixture.

Final real-Postgres checks:

1. Migrations applied twice; pgvector version 0.8.2 confirmed.
2. Qualifier and audit redelivery each left one intact row.
3. Receipt redelivery deduplicated while distinct `step_seq` retained two rows.
4. Ordered legacy work-package projection advanced to the expected current row.
5. Fixed orthogonal 1536-dimensional vectors each recalled the correct synthetic document.
6. Concurrent identical claim deliveries produced one outbox event.
7. Same event key with changed payload and distinct event key reusing task/version were rejected.
8. Conflicting version 1 was rejected after version 3 had become current; no contradictory history committed.
9. Version 2 delivered after version 3 did not roll back the snapshot.
10. Same invocation with another step sequence retained a separate event.
11. Injected projection CHECK failure after event insertion rolled back both event and projection.
12. Deleted synthetic claim projection rebuilt identically from retained events; unrelated work-package projection and outbox count stayed unchanged.
13. Corrupted retained snapshot binding rejected rebuild without changing existing projection.
14. With the unique index deliberately removed, duplicate retained task/version history independently rejected rebuild without changing projection. Fixture repaired its synthetic history and restored the index afterward.

## Remaining proof gates

No live Restate service was installed, selected, registered or exercised. Journal crash/restart, interrupted SQL acknowledgement through an actual Restate invocation, quarantine repair, full journal-backed Postgres recovery, authenticated worker ingress and runtime pipeline integration remain open. SQL redelivery tests prove transaction semantics; they do not establish a deployed durable execution pipeline. Lease delivery delayed by database retries can return a deadline that has already elapsed, so the eventual worker adapter must enforce the returned deadline before starting work; server mutation checks already enforce expiry.
