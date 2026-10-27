# Safe claim and receipt SQL projections — 2026-10-27

Security review found a concrete defect in the initial claim history implementation: full authoritative state serialized lease fencing tokens and unscanned receipt diff/stderr into the SQL outbox and read model. The standalone receipt helper also wrote raw diff/stderr. These paths are corrected before activation.

## Boundary

`ClaimProjectionSnapshot` now has a required `schema_version: 2` and a typed field allowlist. It preserves required object/event identifiers, canonical base revision, stage, version, attempt counts, deadlines and a structured receipt summary. It has **no** lease token, worker/repository free-text label, diff or stderr field. Nested types deny unknown fields. Candidate revisions are retained only when they are canonical full hex revisions; arbitrary timeout revision text becomes absent. Spend metadata must be finite and nonnegative.

The private authoritative `ClaimLeaseState` in Restate still retains its token and exact receipt for worker fencing and receipt replay comparison. Retained event history now contains only typed read-model snapshots, and recovery validates those against the typed projection of the authoritative current state. SQL history is not sufficient to reconstruct private claim capabilities and must never become worker authorization input.

The event validator enforces the typed schema before SQL insertion. SQL-only rebuild validates every retained event against it before replacing the current projection, and fails closed above 10,000 rows rather than silently partially rebuilding. Unscanned or capability-bearing legacy payloads are rejected. Explicit Restate re-export retains the original safe event identities and exact safe payloads.

`project_receipt` writes no raw `diff`/`stderr_tail`; its legacy `diff` column is NULL. Idempotent redelivery clears that column for the corresponding key without adding a row. This is not a global cleanup migration of previously persisted SQL. Unsupported old retained-history schema and in-flight deployment migration remain explicit blockers; no live migration, purge or production registration was performed.

This is scoped to claim and receipt projection paths. It does not claim that all factory audit/memory/qualifier content has passed secret scanning.

## Evidence

- Regression test was RED on the existing full-state serializer: the SQL event included the fencing token. GREEN tests now cover both active and completed lease projections, synthetic diff/stderr canaries, retained private receipt content, nested unknown/token fields and nonrevision text.
- All-feature control-plane library tests: **140 passed**, zero failures/ignored. Strict Clippy for the library and both affected examples passed; rustfmt and diff checks passed.
- Real disposable Restate 1.8.0 / SDK 0.12.1 and Postgres 17.9 / pgvector 0.8.2 fixture passed. SQL rows contain neither the synthetic lease token nor the raw receipt canary, while private Restate status retains both. Full database deletion and recreation followed by SIGKILL/graceful Restate restarts and fresh re-export preserves the original **redacted** keys/payloads exactly. Conflict rollback, persistent quarantine and the runtime 128-event cap still pass.
- The same fixture then creates a new empty disposable database and runs `verify_projection`. Completed diff and failed stderr markers are absent from SQL receipt rows; exact redelivery and distinct-step counts are preserved. Capability-bearing event delivery rejects before insertion. Directly injected unsafe retained text is rejected by SQL rebuild and never reaches the projection. Existing transaction/conflict/dedup/vector tests also pass.
- No raw token values are included in the durable result artifact or fixture failure diagnostics. All fixture-owned child processes and temporary databases/directories were removed; no standing service, real credential or account was touched.

Commands: build both `claim_recovery_fixture` and `verify_projection` examples, then run `python3 clean-room/tests/fixtures/claim_projection_recovery.py`. [Machine-readable result](2026-10-27-safe-claim-projection.json).
