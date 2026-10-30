# Architecture — Clean-Room Software Factory (on Goose)

System design, component boundaries, API surface, infrastructure, and non-functional requirements for a working-MVP dark software factory. Grounded in `dark-software-factory-report.md` §4–§10 and the Phase 5/6 kickoff research in `findings.md`.

## Topology (four planes + two cross-cutting services)

```
                          ┌────────────────────────────────────────────┐
   humans  ── sfctl ──►   │  CONTROL PLANE (Rust + Axum + Restate)      │
   (intent,              │   orchestrator · qualifier · gates · CLI API │
    gates)               └───────┬────────────────────────┬────────────┘
                                │ spawn (durable step)    │
                                ▼                         ▼
                    ┌────────────────────┐    ┌────────────────────────┐
                    │ EXECUTION PLANE     │    │ VERIFICATION PLANE      │
                    │ (worker): goose run │    │ (the WALL): isolated    │
                    │  in a git worktree, │    │  evaluator · holdout    │
                    │  deny-default net,  │    │  scenarios · 3×/2-of-3  │
                    │  no host secrets    │    │  · 90% gate             │
                    └────────────────────┘    └────────────────────────┘
                                │                         ▲
                                └── git diff (draft PR) ──┘
                    ┌────────────────────────────────────────────┐
                    │ MODEL GATEWAY (LiteLLM/Bifrost)             │
                    │  open-weights routing · budget caps ·       │
                    │  virtual keys (credential broker)           │
                    └────────────────────────────────────────────┘
```

## Components

### 1. Control plane — `crates/control-plane` (Rust)
The orchestrator. Owns authoritative state and the goal cascade; does **not** execute agent code (mirrors Temporal's "the service doesn't execute your code").
- **Responsibility**: intent intake, spec decomposition (intent → spec → modules → work packages), qualifier scoring, gate enforcement, spawning/coordinating workers and the evaluator via durable Restate workflows, CLI/HTTP API.
- **Owned data**: Intent, Spec, Module, WorkPackage, QualifierScore, BudgetLedger, CredentialGrant, PromotionRecord, AuditEvent, Receipt (queryable copies).
- **Public interface**: HTTP API (see API Surface) consumed by `sfctl`; internal Restate workflow handlers consumed by the planes.

### 2. Durable state — Restate (workflow journal) + Postgres (queryable records)
- **Restate** (`restate-server`, embedded log + RocksDB + S3 snapshots) owns the **workflow/journal state**: Claim, Lease, Attempt, Cooldown, and the state-machine of each work package's lifecycle. Replay-based, exactly-once, durable timers/awakeables.
- **Postgres 16 + SQLx** owns **queryable/operational records** the CLI and observability need to `SELECT` over: specs, modules, work packages, qualifier scores, budget ledger, credential grants, promotion records, audit events. (See Known Unknowns: whether Postgres can be dropped in favor of the embedded store — debated below.)

### 3. Execution plane — Goose workers (git worktrees)
- Each work package runs in its **own disposable git worktree**, seeded with its typed interface contract.
- **Goose** is invoked **headless** as a subprocess: `goose run --no-session -i <contract> --recipe build.yaml`, `GOOSE_MODE=auto`, pointed at the gateway via a custom `engine:openai` provider (`base_url` = gateway). Exit code + `git diff` in the worktree = the result contract.
- **Isolation**: deny-by-default network (allowlist the gateway + package registry), no inherited host secrets, agent branch + draft PR only. Goose has **no native worktree support**, so the factory creates/tears down the worktree and runs Goose *inside* it.

### 4. Verification plane — the wall (`crates/evaluator`)
The load-bearing isolation. An **isolated evaluator** with its **own credentials** and **no access** to the generator's prompt or output.
- Runs **holdout scenarios** (plain-English BDD, stored where the generator cannot reach them) against an ephemeral deployment, **3× each**, requiring **2-of-3 per scenario** and **90% aggregate** pass.
- Feeds failures back to generation as **opaque one-liners** (`"SQL Injection Detection failed: endpoint returned 500"`) — never the scenario text.
- Runs the deterministic policy/static-analysis layer (lint/typecheck/test/secret-scan) *after* the validator says yes.

### 5. Model gateway — Bifrost
One OpenAI-compatible surface the workers call. **Credential broker**: issues short-lived, task-scoped virtual keys (sent as the `x-bf-vk` header); enforces **per-task budget caps**, rate limits, and central logging. Routes cheap-task → cheap open-weights (M2.5/Qwen/GLM-5-Flash), hard-task → GLM-5.1/DeepSeek-V4-Pro/Kimi K2.5. Runs externally on the operator's network (set `BIFROST_URL`); not containerized by the factory. Budgets are read from Bifrost's governance API (`/api/governance/virtual-keys`).

### 6. CLI — `sfctl` (`crates/sfctl`, clap)
Human surface. Submits intents, inspects qualifier reasoning, watches stages, approves/denies gates, raises budget, stops work (kill switch). `--json` for scripting.

### 7. Command policy — `execution::policy` (R13)
Gates every shell command *before* execution: a shell AST tokenizer (pipes/chains/nesting) + declarative TOML rules (blocked binaries, allowed write paths). Enforced **both** as a PATH shim (`shims/sh`) and via the existing OS isolation (R1/R10) as the hard backstop. Deterministic — no LLM.

### 8. Output masking — `execution::mask` (R14)
Scrubs env tokens, API keys, creds, home paths, IPs, and emails from tool outputs *before* they enter the model context. Records that a redaction occurred (audit event) without recording the secret.

### 9. Coordinator / driver — `control-plane::driver` (R15)
Decomposes a spec into a `Task` dependency DAG, dispatches only unblocked work packages as workers, and enforces a concise-receipt contract (a bounded summary, not a raw log).

### 10. Codebase memory — `control-plane::memory` (R16)
A `tree-sitter` AST graph (defines/calls/deps — deterministic; feeds the qualifier's blast-radius factor) + `pgvector` semantic search on the **existing Postgres** (embeddings via Bifrost). One runtime, one store — no Python.

## API Surface (control plane HTTP, consumed by `sfctl`)

| Method | Route | Auth | Idempotency | Error semantics |
|--------|-------|------|-------------|-----------------|
| POST | `/v1/intents` | operator | `Idempotency-Key` header; returns existing on repeat | 409 on malformed spec; 422 on unmet acceptance-criteria schema |
| GET | `/v1/intents/{id}` | operator | read | 404 unknown id |
| GET | `/v1/work-packages` | operator | read | list with stage/spend/revision |
| GET | `/v1/work-packages/{id}` | operator | read | detail + receipts + evaluation runs |
| POST | `/v1/promotions/{id}/approve` | operator | idempotent | 409 already-approved; 403 not-verified |
| POST | `/v1/grants/{id}/approve` | operator | idempotent | 409 already-approved |
| POST | `/v1/budget/raise` | operator (human-only) | idempotent | 403 below-approval-threshold |
| POST | `/v1/work-packages/{id}/stop` | operator | idempotent | releases lease, cancels worker |
| GET | `/v1/events` | operator | read | append-only audit, cursor-paginated |
| GET | `/v1/evaluations/{id}` | operator | read | wall results (operator-facing; NOT exposed to generator) |

Internal plane coordination is via Restate workflow handlers (claim/release/complete/evaluate), not this HTTP surface.

## Data ownership (from data-map.md)

| Entity | Owning component |
|--------|------------------|
| Intent, Spec, Module, WorkPackage | Control plane (Postgres) |
| QualifierScore, BudgetLedger, PromotionRecord | Control plane (Postgres) |
| AuditEvent | Control plane (append-only Postgres) |
| Claim, Lease, Attempt, Cooldown | Restate (workflow journal) |
| Receipt | Control plane (Postgres) — binds result→claim→stage→git SHA |
| HoldoutScenario | Verification plane (stored unreachable-by-generator) |
| EvaluationRun | Verification plane (Postgres for queryability) |
| CredentialGrant | Control plane (Postgres) + Gateway (broker issue) |

## Integrations

| External | Purpose | Auth | Failure handling |
|----------|---------|------|------------------|
| LiteLLM/Bifrost gateway | model routing + budgets + creds | virtual key per task | retry with backoff; budget exceeded → fail unit, loop to human |
| Goose (subprocess) | coding worker | n/a (local) | non-zero exit → receipt failure; max retries 3/spec |
| Git (worktree + draft PR) | code isolation | SSH/deploy key (scoped) | worktree cleanup on timeout; reconcile via receipt |
| Package registries | build deps | allowlisted egress | deny-by-default blocks others |
| Postgres 16 | queryable records | SQLx pool | standard DB retry |
| Restate server | durable state | local binary | replay/retry handles crash; S3 snapshot restore |

## Infrastructure

- **Deployment target (user clarification)**: the local NUC. Railway is not a deployment target. Host-specific isolation, identities, service supervision and recovery must be verified on the NUC before activation; macOS fixtures do not establish NUC readiness.

- **Deployment (MVP)**: local/dev — `restate-server` binary + Postgres (Docker Compose) + LiteLLM gateway (self-hosted) + `sfctl`. Production path (documented, not built in MVP): Kubernetes Operator for Restate, managed Postgres, gateway as a service.
- **Environments**: `dev` (local). Staging/prod topology is documented but out of scope for the MVP vertical slice.
- **Secrets strategy**: no secret in any agent context. Gateway issues short-lived task-scoped virtual keys; the control plane holds no model credentials beyond a gateway-admin key. A dedicated agent secret set is distinct from developer/CI secrets.

## Non-functional requirements

- **Observability**: every stage transition, tool invocation, spend delta, and reasoning step is an audit event ("lights off, nothing unseen"). Tracing via `tracing` + OTel-compatible export.
- **Durability**: work-package state survives worker crash via Restate replay; receipts reconcile lost executors.
- **Safety**: agent cannot merge/deploy its own change; destructive ops and first-promotion and budget-raises and privileged credentials are human-gated; kill switch always reachable.
- **Performance**: not latency-critical; a unit may take minutes (LLM loop). Restate inactivity timeout raised to ~3 min for LLM calls.
- **Cost**: budget caps enforced at the gateway (per-key) and ledger (per-unit/per-day).

## Alternatives considered and rejected

- **Hand-rolled replay state** (report Path B) → rejected: user chose a durable library (Restate); faster to correct durability.
- **Temporal** → rejected: worker fleet + server + DB heavier than Restate's one binary for an MVP.
- **Hatchet** → rejected: weaker replay/audit story than Restate.
- **OpenHands/SWE-agent as worker** → rejected: user chose Goose as the (only non-clean-room) foundation.
- **MicroVM isolation (E2B/Firecracker)** → deferred: git worktrees are the pragmatic MVP start.

## Security boundaries & blast radius (top 3 risk points)

1. **Generator/validator collusion (sycophancy)** — mitigated by the wall: separate credentials, unreachable scenario store, opaque failure feedback.
2. **Agent gains destructive permission** — mitigated by credential-scoping + human approval for the destructive class + kill switch.
3. **Cost blow-up** — mitigated by gateway per-key caps + ledger per-unit/per-day caps + retry caps.

## Debate Outcomes

A 5-persona adversarial debate (AI Agent Systems, Systems Architect, Rust Backend, AppSec, FinOps) stress-tested this artifact. Full record: `consensus-plan.md` (authoritative) and `debate-transcript.md`. The debate produced 12 resolutions (R1–R12) that **change** the design as originally written above. Key corrections:

1. **Wall isolation is an OS boundary, not a path.** Holdout store enforced by distinct UID + `0700` + a Seatbelt `sandbox-exec` deny-read profile on the generator; evaluator gets `deny network*`. ("unreachable" is now a mechanism, not an adjective.) → R1
2. **Two binaries, not one.** The control plane does NOT spawn Goose. A separate execution-plane worker daemon subscribes to Claim/Lease tasks, runs Goose in a sandbox, and returns the outcome via `ctx.run`/awakeable. → R4
3. **Restate journal is the single source of truth.** Postgres is a read projection fed by an idempotent outbox `(invocation_id, step_seq)`, not a second writer. → R3
4. **The Goose spawn is non-replayed** — subprocess runs outside the journal; only the outcome is journaled; idempotency key = `sha256(invocation_id:step_seq)[..16]`. → R5
5. **Typed `Receipt` replaces "exit code + git diff."** `git diff` is payload; the status discriminator (`Completed|TimedOut|Failed|Crashed`) is parsed from `--output-format json` stdout. → R6
6. **The 2-of-3/90% gate is incoherent as written.** Replaced: LLM validator demoted to a flakiness pre-filter; the real verdict is the deterministic verifier (property tests/typecheck/SAST) + a human promotion oracle. → R2
7. **Budget is a hard cutoff, not a ledger.** Counter in a Restate state object; gateway defaults-deny before each call (fail-closed on partition); `$0.75/unit` ceiling. → R7
8. **Credential broker scopes the git key**, not just model spend: fork-scoped, write-only, push-forbidden-to-main, per-agent ephemeral key. → R8
9. **Kill switch = `kill -pgid SIGKILL` + an out-of-band brake key** on a separate watchdog, independent of the operator token. → R9
10. **Worker isolation by identity** (distinct uid, empty home, no agent socket, whitelisted env), not env scrubbing. → R10
11. **Deterministic checks run BEFORE the validator** (pre-promotion, unconditional, blocking). → R11
12. **Cost figure corrected ~15× → ~4×** (inference-only), and the serving backend is the open cost question. → R12

O1 is resolved to hosted open-weights via external Bifrost. O4 is resolved (2026-10-26) to a separate local operator account and action-bound approval channel, with no MFA claim. The scoped three-reviewer debate and explicit user selection are recorded in `decisions/2026-10-26-operator-auth.md`. The private Unix transport checks actual kernel peer UID; immutable approval records bind the operation, task/repository/ref, exact candidate/base SHA, evidence digest, audience, nonce and expiry. Journal consumption does not itself execute a promotion. Distinct accounts, protected ingress and replay-safe execution still need runtime verification. O2/O3/O5/O6 retain their documented follow-on work in `consensus-plan.md`.

## Scoped structured writer — 2026-10-28

Three-reviewer debate selects a two-file, factory-owned structured MCP writer for the uncapped owned INT-LOOP; shell policy stays unchanged. Distinct fixed executor invocation, strict bytes/identity/fences, partial-write quarantine, exact baseline/generation snapshot and isolated evaluation remain mandatory. No production activation or completed INT-LOOP is claimed. See `decisions/2026-10-28-structured-task-writer/consensus-plan.md` for the decision and discriminating pre-live gates.

## NUC protected deployment — 2026-10-29

A three-reviewer researched debate with actual late-start canary and one concession round selects the guarded root-owned systemd supervisor outside Docker, immutable generation catalogue, durable one-way closure and separate nonroot brake frontend/root stop backend. Existing bo is the human operator relative to five new locked service identities, without MFA or same-UID-compromise resistance claims. Actual identity installation is additive; protected runtime/socket/namespace and complete recovery/integration gates remain open. See `decisions/2026-10-29-nuc-root-supervisor/consensus-plan.md` and `verification/2026-10-29-nuc-identities/README.md`; do not treat the bounded freeze test or provisioned identities as full production containment.
