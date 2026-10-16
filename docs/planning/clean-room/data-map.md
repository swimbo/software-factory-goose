# Data Map

Data entities, relationships, flows, access patterns, and storage requirements for the clean-room software factory.

## Storage substrate

- **Durable orchestration state → Restate** (replayable workflow/journal state: claims, leases, attempts, receipts, cooldowns). Restate owns the append-only event log and replay/retry/timer semantics.
- **Operational/queryable records → PostgreSQL** (the "one Postgres box" pattern; also what Restate can back onto): specs, modules, work packages, scenarios, qualifier scores, budget ledgers, credential grants, audit log. SQLx for compile-time-checked queries.
- **Agent output / diffs → git** (worktrees + branches + draft PRs) plus an artifact store (worktree path + receipts referencing exact git revisions).

## Entities

### 1. Intent
- **id** (ULID), **title**, **description** (plain English, machine-checkable), **acceptance_criteria** (list), **author**, **created_at**, **status** (draft → triaged → claimed → building → evaluating → merged | human_lane | rejected).
- **qualifier_score**, **lane** (dark | human), **lane_reason**.
- Derived from human input; immutable after triage (audit-by-design).

### 2. Spec (inception output)
- **id**, **intent_id** (FK), **body** (versioned markdown), **modules[]**, **dependency DAG**, **created_at**, **version**.
- The machine-derivable translation of intent into testable description of "correct".

### 3. Module
- **id**, **spec_id** (FK), **name**, **typed_interface_contract** (the key clean-room idea — builders implement *to a contract* without coordinating), **dependencies[]** (DAG edges), **status**.

### 4. Work Package (unit of dark-lane work)
- **id**, **module_id** (FK), **contract_ref**, **estimated_scope**, **status** (queued → claimed → building → checkpointed → evaluating → merged | failed), **retry_count**, **budget_allocation**.

### 5. Claim
- **id**, **work_package_id** (FK), **worker_id**, **git_revision** (pinned), **lease_expiry**, **claimed_at**, **status** (open | released | expired | fulfilled).
- Owns "who is working on what" — prevents double-claim.

### 6. Lease
- **id**, **claim_id** (FK), **expires_at**, **renewed_at**, **cancelled_at**.
- Bounds ownership in time; enables reconciliation after a lost/crashed worker.

### 7. Attempt
- **id**, **work_package_id** (FK), **attempt_number**, **started_at**, **ended_at**, **outcome** (success | failure | timeout | cancelled), **spend_usd**, **token_usage**.
- Budget + retry accounting (cap ~3/spec per report).

### 8. Receipt
- **id**, **attempt_id** (FK), **claim_id**, **git_revision** (exact), **diff_ref**, **result_summary**, **exit_code**, **created_at**.
- Binds result → claim → stage → exact git revision; the reconciliation backbone (report: "more rigorous than what Hatchet ships").

### 9. Holdout Scenario
- **id**, **work_package_id** (or module-level), **body** (plain-English BDD), **storage_location** (MUST be unreachable by the generator), **runs[]** (3 per evaluation), **pass_threshold** (2-of-3), **created_at**.
- The "wall" content. Never stored next to the implementation; never shown to the generator.

### 10. Evaluation Run (wall output)
- **id**, **scenario_id** (FK), **attempt_id** (FK), **run_number** (1..3), **result** (pass | fail), **failure_message** (opaque one-liner fed back), **aggregate_pass_rate**, **created_at**.
- Enforces 2-of-3 per scenario and 90% aggregate.

### 11. Qualifier Score / Decision
- **id**, **intent_id** (FK), **score**, **factors** (JSON: spec clarity, blast radius, novelty, reversibility), **lane**, **decided_at**, **decided_by**.
- "The scoring function, not the agents, is the real product" (gethuman.sh).

### 12. Budget Ledger
- **id**, **envelope_total**, **per_unit_cap**, **per_day_cap**, **spent_to_date**, **owner** (human), **approval_required_above**.
- Hard cap; only a human raises the envelope (Gate 2).

### 13. Credential Grant (broker record)
- **id**, **work_package_id** (FK), **scope** (single-repo, single-action), **kind** (agent-mail self-issued vs broker-issued), **ttl**, **issued_at**, **expires_at**, **human_approval_required** (bool), **approved_by**.
- Short-lived, task-scoped; destructive/privileged class requires human approval (Gate 3).

### 14. Promotion Record (Gate 1)
- **id**, **work_package_id** (FK), **target_env**, **verification_ref**, **human_approval** (pending | approved | denied), **approved_by**, **promoted_at**, **is_first_promotion** (bool).
- First promotion is a human act; subsequent drift goes dark.

### 15. Audit Event
- **id**, **timestamp**, **actor** (agent | human | system), **action**, **entity_id**, **entity_type**, **metadata** (JSON), **git_revision**.
- Append-only; "lights off, nothing unseen."

### 16. Policy Rule (R13)
- **id**, **blocked_binaries[]**, **allowed_write_paths[]**, **version**, **source** (`policy.toml`).
- Declarative, deterministic; loaded by the command-policy engine.

### 17. Task (R15)
- **id**, **subject**, **description**, **status** (pending | in_progress | completed | deleted), **blocked_by[]**, **blocks[]**, **owner**, **active_form**.
- The work-package dependency DAG; `blocked_by` gates dispatch.

### 18. AST Node / Edge (R16)
- **node**: **id**, **symbol**, **kind** (fn | struct | trait | mod | …), **file**, **git_revision**.
- **edge**: **from_node**, **to_node**, **kind** (defines | calls | imports).
- Deterministic structural graph; rebuilt per revision by `tree-sitter`.

### 19. Embedding (R16)
- **id**, **content** (chunk), **vector** (pgvector), **source** (file/revision), **model** (embedding model via Bifrost), **created_at**.
- Semantic layer; ANN-searched for convention recall. Stored in the same Postgres (`pgvector`).

### 20. Mask Event (R14)
- **id**, **attempt_id**, **timestamp**, **pattern_kind** (api_key | pem | home_path | …), **output_ref**.
- Records *that* redaction happened (never the secret itself).

## Relationships (high level)

```
Intent 1───1 Spec 1───N Module 1───N WorkPackage
                                     │
                     ┌───────────────┼───────────────┐
                     │               │               │
                   Claim 1───1 Lease  │          Budget Ledger
                     │               │
                   Attempt 1───N Receipt
                     │
                   EvaluationRun ───N HoldoutScenario
                                     │
                              CredentialGrant
                              PromotionRecord
                              QualifierScore (per Intent)
                              AuditEvent (per everything)
```

## Flows

1. **Intake** — human submits intent → qualifier scores → lane assigned (dark or human).
2. **Inception** — dark-lane intent → spec + modules + typed contracts + DAG (machine-derivable, versioned markdown).
3. **Claim/execute** — worker claims a work package in a git worktree, Goose runs headless, receipt bound to exact revision.
4. **Verify (the wall)** — isolated evaluator runs holdout scenarios (triple-run, 2-of-3, 90% gate); opaque one-liner failures feed back to generation.
5. **Gates** — budget cap; destructive-op approval; credential issuance; first-promotion approval.
6. **Merge/deploy** — existing CI/CD after gates clear; agent cannot merge/deploy its own change.
7. **Observe** — audit events + drift sweep.

## Access patterns

- **Write-heavy, append-only** audit log (audit events, receipts, evaluations).
- **Read** for status/observability (CLI `sfctl status`, list claims/receipts).
- **Lease renewal** — periodic, low-latency.
- **Scenarios are read by the evaluator only**, never by the generator — enforced by storage location + credential separation.

## Storage requirements

- Postgres 16 (SQLx) for entities 1–15's queryable records.
- Restate for workflow/journal state (claims/leases/attempts/cooldowns as durable steps).
- Git (worktrees + branches) for code/diffs; receipts store exact SHAs.
- No secrets in any table — credential grants store a *reference* to a broker-issued short-lived token, never the token value.
