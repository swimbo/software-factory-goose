# Consensus Plan — Clean-Room Software Factory (on Goose)

Produced by a 5-persona adversarial debate (AI Agent Systems, Systems Architect, Rust Backend, AppSec, FinOps) over `architecture.md`. This is the revised, debate-hardened set of decisions. Supersedes the original architecture.md where they conflict.

## Resolved decisions (consensus)

### R1 — The wall's isolation is an OS boundary, not a path convention
The holdout store is enforced by **UID + mandatory-access-control**, not "unreachable" as an adjective. Single-host macOS MVP:
- Distinct UIDs: `uid_gen` (generator worker), `uid_val` (evaluator), `uid_store` (holdout store owner).
- Holdout store at `/var/holdout`, owned `uid_store`, mode `0700` — DAC blocks the worker uid.
- Generator runs under a **Seatbelt** `sandbox-exec` profile: `(deny file-read* (subpath "/var/holdout"))` — kernel-enforced after DAC.
- Evaluator runs under `(deny network*)` so it cannot leak verdicts back to the generator over any side channel.
- Mount/container is the *escalation* path if cross-host or root-capable build is ever needed — not the MVP boundary.

### R2 — The gate is a flakiness pre-filter + deterministic verifier + human oracle (not a statistical quality claim)
The original 2-of-3/90% was incoherent (n=3 has no statistical power; denominator undefined). Resolution:
- **LLM validator is demoted to a cheap pre-filter** (per-scenario 2-of-3 is kept only as a flakiness-tolerant tiebreaker, with the denominator defined as "all runs across all scenarios").
- **The wall's actual verdict = the deterministic verifier** (executable property tests, type checks, secret-scan, SAST) — no learned weights, cannot be sycophantic.
- **Promotion is a human oracle** — the merge is human-approved, gated by the out-of-band brake, never by a model's say-so.
- Model independence: generator and validator must be **different model families** (a cross-family check reduces but does not eliminate shared-preference bias — the deterministic verifier is the real anchor).

### R3 — Single source of truth: Restate journal; Postgres is a projection
- Restate journal is the **write-side source of truth** for all lifecycle state (invocation, claims, leases, attempts, cooldowns, budget ledger).
- Postgres is a **read model** fed by an idempotent outbox keyed `(invocation_id, step_seq)`; `INSERT ... ON CONFLICT DO NOTHING`; reconstructible by replaying the outbox. One writer, many readers.

### R4 — Two binaries: control plane ≠ execution plane
- **Control plane**: owns the journal, Claim/Lease task queue, credential grants, the gate. Does NOT spawn Goose.
- **Execution plane**: an independently-deployed worker daemon that *subscribes* to Claim/Lease tasks from a durable queue, runs Goose in a sandbox (distinct uid, cgroup, no ambient credentials), and writes completion back via `ctx.run`/awakeable.
- The two communicate only through the durable queue + outbox, never a shared process boundary.

### R5 — The Goose spawn is non-replayed; only its outcome is journaled
- Subprocess runs **outside** the journal; the spawn *decision point* is journaled via `ctx.run`, and only the completion outcome is recorded.
- Idempotency key = `sha256("{invocation_id}:{step_seq}")[..16]`.
- On replay, the durable step returns the recorded outcome (never re-spawns); `kill -pgid` reaps any still-running subprocess from the prior attempt.

### R6 — Typed Receipt; `git diff` is payload, not status
```rust
enum Receipt {
    Completed { sha, diff, turn_count, exit_code, wall_time_ms },
    TimedOut  { sha, turn_count, wall_time_ms },
    Failed    { exit_code, stderr_tail },
    Crashed   { signal, core_dumped },
}
```
stdout = the single JSON line (`--output-format json`); stderr = logs, never parsed as status. Non-JSON stdout → `Failed`/`Crashed`, not a silent fallback.

### R7 — Budget is a hard technical cutoff, not a ledger
- Counter lives in a **Restate state object**; every billable call updates it atomically in the same journal write.
- Gateway **defaults-deny**: before each inference call, reads the Restate budget and refuses if `spent + estimate > ceiling`. If it cannot read the budget (Restate down/partition), it **denies** — fail-closed, never fail-open.
- Exhaustion returns a 402-style terminal state (not retryable); gateway is the only route to inference, so gateway-denial = loop death.
- Dollar ceiling per unit: `$0.75` (≈1.5× nominal of 3 generations + 9 verification passes). Retry count (3) is retained as a *count* bound, but the dollar ceiling is the *cost* bound.

### R8 — Credential broker scopes the git key, not just model spend
Git deploy key spec: **fork-scoped** (registered on the agent's fork only, never origin), **write-only** (no `admin`/`maintainer`), **push-forbidden-to-main** (branch protection; write only to `agent/*` pattern), **per-agent ephemeral key** rotated per run. The key can never close the loop from generated code to merged code.

### R9 — Kill switch = `kill -pgid` + an out-of-band brake key
- Primitive: `kill(-pgid, SIGKILL)` targets the whole process tree (Goose + sandbox + shell), then reap.
- The brake key is a **second, independent credential** on a separate watchdog, reachable only via loopback-only unix socket, **not** dependent on the operator token. If the operator token is exfiltrated, the agent still cannot touch the brake key.

### R10 — Worker isolation is by identity, not env scrubbing
Distinct uid, empty home, no `SSH_AUTH_SOCK`, whitelisted env, closed fds, explicit cwd, loopback explicitly denied to control plane/Postgres/evaluator. "No inherited secrets" enforced by identity, not by scrubbing.

### R11 — Deterministic checks run BEFORE the validator
Secret-scan + SAST + typecheck are a **pre-promotion, unconditional, blocking CI gate** that runs before the model validator. The validator is then *advisory*; the human promotion step is the true gate.

### R12 — Cost figure corrected: ~4×, not 15×
Inference-only unit cost is ~4× cheaper ($2.90 vs $11.80/run, ~75% lower), not 15×. It is NOT a headline total-savings multiplier. The correct total-cost claim is **undefined until the serving backend is named** (see open items).

## Resolved decisions (R13–R16) — folded in 2026-10-15

Gleaned from the `code-machine` architecture analysis; see `improvements-plan.md` for tasks/verification.

### R13 — Deterministic pre-execution command policy
A `policy` module (shell AST parse + declarative TOML rules) gates every shell command **before** execution — catching blocked binaries and unauthorized write paths. Enforced **both** as a PATH shim (fast, deterministic, no LLM) and via the existing OS isolation (hard backstop). This is the cheap layer R11 wanted before the validator.

### R14 — Output masking before the model context
Tool outputs are scrubbed (env tokens, API keys, creds, home paths, IPs, emails) **before** they enter the model context. Closes the gap where R10 covers secret *injection* but not secret *leakage* in outputs.

### R15 — Coordinator + task-dependency graph
The goal cascade becomes a first-class dependency DAG (`Task` with `blocked_by`/`blocks`); the driver (coordinator) dispatches only unblocked work packages as workers, and each worker returns a **concise structured receipt**, not a raw log flood.

### R16 — Dynamic codebase memory
codified knowledge becomes queryable: a `tree-sitter` AST graph (defines/calls/deps — deterministic, feeds the qualifier's blast-radius factor) + `pgvector` semantic search on the **existing Postgres** (embeddings via Bifrost). **No ChromaDB / no Python** — one runtime (Rust), one store (Postgres).

## Open items (need resolution before/early in implementation)

### O1 — Serving backend — RESOLVED: hosted open-weights API
**Decision (user, 2026-10-13): hosted open-weights endpoints** (OpenRouter / Z.ai API / together.ai). No GPU ops; pay per-token markup. Self-hosted GPUs (vLLM/SGLang) deferred until volume and a real cost model warrant revisiting.

### O2 — Gate sample size (n)
The debate produced a tension: statistical rigor wants more samples (n=400 Clopper–Pearson) but cost wants fewer (~9 verification passes). MVP resolution: cost-bounded — keep 2-of-3 flakiness as a pre-filter + deterministic verifier + human oracle, defer the statistical-rate gate until volume warrants it. Revisit in a later phase.

### O3 — Qualifier spec is a required follow-on document
Inputs (executable spec, artifact, trace, run metadata, env fingerprint) → score Q ∈ [0,1] + fatal flag → dark-lane threshold (Q < 0.60 or fatal) → calibration loop (weekly human re-rate, agreement threshold, re-weight). The qualifier "is the real product" and needs its own spec doc before implementation of the qualifier module.

### O4 — Operator auth, MFA on gates, key rotation/revocation
No persona specified a concrete operator authz model (mTLS? OIDC? local CLI token?). Must be decided before the gates are implemented. Gate approval should carry a second factor / out-of-band confirmation.

### O5 — Scenario authoring, coverage, and drift sweep
Who writes holdout scenarios, how coverage is measured, and a drift-sweep loop that adds scenarios through the same gate (to prevent overfitting to a fixed set). Unowned in the original plan.

### O6 — Supply-chain: generator as attacker
Poisoned dependency `postinstall` executing with worker privileges. Mitigate via locked deps + SBOM + registry egress allowlist + running the build in the same sandbox as the agent.

## Blind spots carried into the plan
- Ephemeral worktree/deployment lifecycle (create/teardown/gc on crash) — owned by the execution plane.
- Contract schema + typed API versioning (Receipt, Claim, CredentialGrant payloads) — needs a schema (JSON Schema / typed structs).
- The wall's own judging-model cost + evaluator deployment isolation.
