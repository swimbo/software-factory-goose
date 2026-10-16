# Phase 3 — Data Map

**Status: complete.**

## Objective
Map data entities, relationships, flows, access patterns, storage requirements.

## Done
- `data-map.md` defines 15 entities (Intent, Spec, Module, WorkPackage, Claim, Lease, Attempt, Receipt, HoldoutScenario, EvaluationRun, QualifierScore, BudgetLedger, CredentialGrant, PromotionRecord, AuditEvent) with relationships, flows, access patterns, and storage.
- Kickoff research folded into `findings.md` (Restate embedded-store correction).

## Verification (Hard Gates)
- [x] Entity inventory with lifecycle.
- [x] Relationships (adjacency + cardinality).
- [x] Flows (intake → inception → execute → verify → gates → merge).
- [x] Access patterns (write-heavy audit, read-heavy status).
- [x] Storage requirements (Restate journal + Postgres projection + git).
- [x] Identifiers (ULID/uuid v7).
- [x] Consensus R3 (single source of truth) captured in `consensus-plan.md`.

## Open item
Serving backend (O1) affects BudgetLedger cost fields — resolve before Phase 9.

## Exit signal
Data shape fixed; Architecture can commit to table shapes.
