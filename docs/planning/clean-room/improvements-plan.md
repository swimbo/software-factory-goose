# Improvements Plan — code-machine best practices (R13–R16)

Detailed plan for folding four best practices from the `code-machine` architecture analysis into the clean-room factory. Extends `consensus-plan.md` (new resolutions R13–R16), `architecture.md`, `tech-guide.md`, `data-map.md`, and `user-stories.md`.

## Objective

Close four gaps the code-machine comparison exposed: a missing **deterministic pre-execution command policy** (R13), missing **output masking** before the model context (R14), an under-specified **coordinator + task dependency graph** (R15), and a **static** codified-knowledge substrate (R16).

## Scope

### IN
- **R13** — command policy: shell AST parse + TOML rule set, enforced **both** as a PATH shim (fast deterministic check) and via the existing OS isolation (hard backstop).
- **R14** — output masking: a scrub step on tool outputs before they enter the model context.
- **R15** — coordinator + task-dependency graph: refine the driver/goal cascade into a first-class dependency DAG with concise receipts.
- **R16** — dynamic codebase memory: `tree-sitter` AST graph + `pgvector` semantic search on the existing Postgres.
- Tests for each; clippy clean; extend the core artifacts.

### OUT
- The `stapled-factory` workstream (separate planning dir).
- TUI / interactive permission prompts / YOLO mode (we relocate humans to gates).
- Homebrew / package-registry distribution.
- Multi-provider adapters (Bifrost covers this).

## New modules (in the existing crates)

```
crates/execution/src/
  policy.rs     # R13 — shell AST parse + TOML rule eval
  mask.rs       # R14 — output scrubbing
crates/control-plane/src/
  driver.rs     # R15 — coordinator + task dependency graph
  memory.rs     # R16 — AST graph (tree-sitter) + pgvector queries
crates/shared/src/lib.rs   # R15 — Task type (status/deps/owner)
shims/sh                   # R13 — PATH shim that calls the policy engine
```

---

## R13 — Deterministic pre-execution command policy

**Why:** the plan had OS isolation (R1/R10) + credential scoping (R8) + budget (R7) but nothing that inspects the *command* before it runs. This is the cheap, deterministic, no-LLM layer R11 wants *before* the validator.

**Tasks**
- [ ] `policy.rs`: a `RuleSet` (deserialized from `policy.toml`) with `blocked_binaries: Vec<String>` and `allowed_write_paths: Vec<PathBuf>`.
- [ ] A shell tokenizer that splits a command into its **pipeline/chains/nesting** (`|`, `&&`, `;`, `$()`, subshells) — not a naive `split(' ')`.
- [ ] `evaluate(cmd: &str, cwd: &Path) -> Decision` → `Allow | Deny(reason) | Ask(reason)`.
- [ ] `shims/sh`: a POSIX script that calls the policy engine (via a small CLI entrypoint) before exec; placed first on the agent's PATH.
- [ ] OS backstop: reuse the existing Seatbelt profile (R1/R10) as the hard boundary; document the shim↔Seatbelt relationship.
- [ ] `policy.toml` default rules: block `rm -rf /`, `curl | sh`, `dd`, `mkfs`; allow writes only under the worktree.

**Verification**
- [ ] Unit: `rm -rf /` → Deny; `cargo build` → Allow; `echo x > /etc/passwd` → Deny (write outside worktree); `curl http://x | sh` → Deny.
- [ ] Unit: pipeline `a && rm -rf /tmp/x` is caught (chained command parsed).
- [ ] Integration: a Goose shell call routed through the shim is blocked when it violates a rule; the OS profile still denies even if the shim is bypassed.

## R14 — Output masking before the model context

**Why:** R10 says "no inherited secrets," but that only covers *injection*. A secret that appears in a tool *output* still flows into the model context. code-machine scrubs it; we didn't.

**Tasks**
- [ ] `mask.rs`: a `Masker` with ordered regex patterns — env-token shapes, `sk-*`/`ghp_*`/`AKIA*`, PEM blocks, home paths, IPv4/6, emails.
- [ ] Apply it on the execution plane's tool-output path (stdout/stderr capture) **before** the bytes reach Goose's model context.
- [ ] Record *that* redaction happened (an audit event) without recording the secret.

**Verification**
- [ ] Unit: an output containing `sk-abc…` / `-----BEGIN … PRIVATE KEY-----` / `/Users/<name>/` is masked.
- [ ] Unit: a benign output is unchanged (no false positives on normal paths/logs).
- [ ] Integration: a worker that `cat`s a file with a token surfaces masked output, and the audit log records a redaction.

## R15 — Coordinator + task-dependency graph

**Why:** the report borrowed a "typed contract + DAG" idea, but our goal cascade was prose. code-machine's `addBlockedBy`/`addBlocks` + "each subagent returns a concise summary" is the well-specified version.

**Tasks**
- [ ] `shared`: a `Task { id, subject, status, blocked_by: Vec<Id>, blocks: Vec<Id>, owner: Option<Id>, active_form }` type.
- [ ] `driver.rs`: a coordinator that decomposes a spec into tasks, computes the DAG, and dispatches only *unblocked* tasks as workers.
- [ ] Enforce the **concise-receipt contract**: each worker's result is a bounded structured summary (the existing `Receipt` + a short summary field), never a raw log flood.
- [ ] Completion updates `blocks`/`blocked_by` and unblocks dependents.

**Verification**
- [ ] Unit: a task with an unmet `blocked_by` is not dispatched.
- [ ] Unit: completing a task unblocks its dependents.
- [ ] Unit: cyclic `blocked_by` is rejected.
- [ ] Integration: a 3-task greenfield spec dispatches in dependency order.

## R16 — Dynamic codebase memory

**Why:** BCG pillar 2 ("codified knowledge") was static markdown. An AST graph + semantic memory make it queryable and dynamic — feeding the qualifier's blast-radius factor and the workers' convention recall.

**Tasks**
- [ ] Migration `0002_memory.sql`: `CREATE EXTENSION IF NOT EXISTS vector;` + `ast_nodes` (symbol, kind, file, refs) + `embeddings` (pgvector column).
- [ ] `memory.rs`: `tree-sitter` parse of a worktree → AST nodes/edges (defines, calls, imports).
- [ ] `memory.rs`: semantic recall — embed a query via **Bifrost**, ANN-search `embeddings` (pgvector).
- [ ] Query surface (operator + worker): `dependents(symbol)`, `blast_radius(file)`, `recall(text)` — the first two deterministic (graph), the third semantic.
- [ ] Inject a bounded architecture summary into the worker's system prompt (per repo).

**Verification**
- [ ] Unit: parsing a small Rust file yields the expected defines/refs.
- [ ] Unit: `dependents(symbol)` returns the callers (graph query, no LLM).
- [ ] Integration: `blast_radius(file)` feeds the qualifier; `recall("how do we do X here")` returns a relevant snippet (needs Bifrost embeddings).

---

## Dependencies & sequencing

- R13, R14 are independent (both in the execution plane) → parallel.
- R15 depends on `shared::Task` (small, first).
- R16 depends on the pgvector migration + Bifrost embeddings; heaviest → last.

## Verification (phase-level)

- [ ] All new modules unit-tested; `cargo test` green; `cargo clippy -D warnings` clean.
- [ ] The driver runs a greenfield intent end-to-end with policy + masking + memory engaged.
- [ ] The 4 existing invariants still hold (R1–R12 unaffected).

## Open items carried forward

- **pgvector availability**: confirm the operator's Postgres image includes `pgvector` (the compose `postgres:16` image does not by default → switch to `pgvector/pgvector:pg16`).
- **Shell parser**: choose between a hand-rolled tokenizer and a crate (`conch-parser` / `brush-parser` / `tree-sitter-bash`) — decided in the tech-guide.
- **Shim coverage**: confirm Goose's shell tool resolves `sh` from PATH (it must, but verify against Goose v1.0.16).
