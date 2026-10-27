# User Stories

Derived from requirements (the clean-room dark factory, §1–11 of the report) and pain-point findings (`findings.md#pain-point-research`). The "users" are: the **factory operator** (the human who owns the factory and sits at the three gates), the **intent author** (a human describing what should be built), and the **system/worker** (the Goose agents and control plane acting autonomously). Priorities: **P0** = must-have for the MVP vertical slice; **P1** = should-have; **P2** = later.

## Pain-point → story traceability

| Pain point (findings.md) | Stories it motivates |
|--------------------------|----------------------|
| Sycophancy / self-declared victory | US-6, US-7, US-8 (the wall) |
| Vendor benchmark inflation | US-5 (gateway, independent model choice) |
| "Automating chaos" | US-3 (codified knowledge as prerequisite) |
| Cost blow-up | US-9, US-10 (budget gate) |
| Scaffold matters as much as model | US-4 (Goose as headless, auditable worker) |
| Isolation theater | US-5, US-11, US-12 (worktrees, brokered creds) |

---

## Operator stories (the human at the gates)

### US-1 — Submit an intent and get a lane decision (P0)
As an intent author, I want to submit a plain-English description of what should be built, so the qualifier scores it and tells me whether it goes to the dark lane or is left for a human.
- **Acceptance criteria**: submitting an intent via `sfctl submit` returns a `lane` (dark|human), a score, and a human-readable reason. The intent is stored and immutable after triage.

### US-2 — Review the qualifier's reasoning (P0)
As an operator, I want to see *why* a unit was routed dark vs human, so I can trust (and later tune) the scoring function.
- **Acceptance criteria**: `sfctl inspect <intent>` shows the qualifier factors (spec clarity, blast radius, novelty, reversibility) and the resulting lane.

### US-3 — Enforce codified knowledge before work starts (P1)
As an operator, I want the factory to refuse to run a unit against a repo lacking `AGENTS.md`/codified knowledge, so we don't "automate chaos."
- **Acceptance criteria**: a unit targeting a repo without the required knowledge files is flagged human-lane with a clear reason, not silently dark-laned.

### US-4 — Watch a unit move through stages (P0)
As an operator, I want to observe each work package's stage (queued → claimed → building → evaluating → merged), so "the lights may be off but nothing goes unseen."
- **Acceptance criteria**: `sfctl status` lists active work packages with stage, worker, spend, and current git revision; every transition is an audit event.

## Gate stories

### US-5 — Route models through a gateway with per-task budget (P0)
As an operator, I want the workers to call open-weights models (GLM-5/DeepSeek-V4) through one OpenAI-compatible gateway, with per-task budget caps, so we get cost control and no vendor lock-in.
- **Acceptance criteria**: the worker's model calls go through the gateway; a per-unit spend cap stops a unit that exceeds it.

### US-6 — The generator never sees the holdout scenarios (P0)
As an operator, I want acceptance scenarios stored where the generator cannot reach them, so the wall is real and not theater.
- **Acceptance criteria**: holdout scenarios live in a location the generator has no credential/path access to; the generator's prompt and file reads cannot surface them (verified by an integration test).

### US-7 — Triple-run holdout evaluation with a hard gate (P0)
As an operator, I want each scenario run three times against an ephemeral deployment, requiring 2-of-3 passes and a 90% aggregate, so a bad change can't slip through a single lucky run.
- **Acceptance criteria**: the evaluator runs each scenario 3×; a unit with <2-of-3 on any scenario or <90% aggregate is rejected and looped back with an opaque one-line failure.
- **Controlling consensus R2/R11**: passing this pre-filter is advisory and never sufficient for promotion; deterministic checks and the human promotion oracle remain required.

### US-8 — Failures feed back as opaque one-liners (P0)
As an operator, I want the generator to receive only "`<Scenario>` failed: endpoint returned 500" — never the scenario text — so it can't game the test.
- **Acceptance criteria**: failure feedback to the generator contains no scenario body; the scenario text is only visible to the evaluator.

### US-9 — Human raises the budget envelope, agents spend within it (P1)
As an operator, I want a hard budget cap that agents spend within and only a human can raise, so costs are bounded before they blow up.
- **Acceptance criteria**: exceeding the per-unit or per-day cap triggers a human-approval gate, not silent overage; retries are capped (~3/spec).

### US-10 — Destructive operations require human approval (P1)
As an operator, I want destructive ops (drop DB, rotate root key, cross regulated-data boundary) to require my explicit approval, so an agent can't take an irreversible action.
- **Acceptance criteria**: a destructive op in a runbook/patch is blocked until a human approves; there is a human kill switch.

### US-11 — First production promotion is a human act (P1)
As an operator, I want promotion to require my approval of the promotion decision (not just the diff), bound to its exact revision and verification evidence.
- **Acceptance criteria (reconciled to controlling consensus R11 and O4)**: `verification.yaml` passing is necessary but not sufficient; human approval must bind the exact candidate/base revision and evidence. The earlier automatic-drift bypass is superseded by R11's human promotion oracle. No deployment is inferred from verification alone.

### US-12 — Credentials are brokered, short-lived, and task-scoped (P1)
As an operator, I want agents to receive short-lived, single-repo, single-action tokens via a broker (never a raw secret in their context), with a human approval step for the destructive/privileged class.
- **Acceptance criteria**: no secret value appears in an agent's context; grants are task-scoped with a TTL; privileged grants require human approval.

## Worker/system stories (the autonomous loop)

### US-13 — Claim a work package in an isolated worktree (P0)
As the control plane, I want each worker to run in its own disposable git worktree with deny-by-default network and no inherited host secrets, so blast radius is mechanically bounded.
- **Acceptance criteria**: each unit gets a fresh worktree; outbound network is denied except allowlisted registries/APIs; no dev/prod secrets are present.

### US-14 — Run Goose headless with an exit-code + diff contract (P0)
As the control plane, I want to invoke Goose non-interactively (`goose run`) to do a self-contained coding task and return a diff + exit code, so the agent is a headless worker, not a chat box.
- **Acceptance criteria**: a successful run returns exit 0 + a diff; a failed run returns non-zero + a receipt; no interactive input is required.

### US-15 — Decompose a spec into typed-contract modules (P1)
As the control plane, I want to split a spec into modules with a dependency DAG and typed interface contracts, so parallel builders implement to a contract without coordinating.
- **Acceptance criteria**: a spec produces a DAG of modules each with a typed contract; parallel builders share no mutable state.

### US-16 — Bind a receipt to an exact git revision (P0)
As the control plane, I want every result bound to the exact git revision that produced it, so a lost/crashed worker can be reconciled.
- **Acceptance criteria**: a receipt records result → claim → stage → exact SHA; a timeout can be reconciled against the receipt.

## Improvements stories (R13–R16, from the code-machine analysis)

### US-17 — Block dangerous commands before they run (P0)
As an operator, I want every shell command the agent wants to run checked against a declarative policy *before* it executes, so a destructive command is stopped deterministically — not by an LLM's judgment after the fact.
- **Acceptance criteria**: `Given` a command matching a blocked rule (e.g. `rm -rf /`, `curl … | sh`), `When` the agent attempts it, `Then` it is denied pre-execution with a reason. `Given` a chained/piped command, `When` evaluated, `Then` the dangerous segment is parsed and caught. A normal build command is allowed.

### US-18 — Mask secrets in tool output (P0)
As an operator, I want tool outputs scrubbed of secrets before they reach the model, so a leaked credential can't enter the context even if the agent cats a secret-bearing file.
- **Acceptance criteria**: `Given` an output containing an API-key shape or a PEM block, `When` it is captured, `Then` it is masked before reaching the model. `Given` a benign output, `Then` it is unchanged. A redaction is recorded as an audit event without the secret.

### US-19 — Dispatch work packages by dependency (P1)
As the control plane, I want work packages expressed as a dependency DAG and dispatched only when unblocked, with each worker returning a concise structured receipt, so parallel builders don't coordinate implicitly and the coordinator's context isn't flooded.
- **Acceptance criteria**: `Given` a task with an unmet `blocked_by`, `Then` it is not dispatched; `When` its blocker completes, `Then` it unblocks. A cyclic dependency is rejected. A worker's result is a bounded summary, not a raw log.

### US-20 — Query codebase structure and memory (P1)
As the qualifier/worker, I want to query what a file depends on (deterministic, from an AST graph) and recall relevant conventions (semantic), so blast-radius scoring and code changes are grounded in the repo's actual structure.
- **Acceptance criteria**: `Given` a symbol, `Then` `dependents(symbol)` returns its callers from the graph with no LLM. `Given` a file, `Then` `blast_radius(file)` returns its reverse-dependency set. `Given` a free-text query, `Then` semantic recall returns a relevant snippet (embeddings via Bifrost).

---

## Out-of-scope (deferred) stories

- Web dashboard for observability (US-4 CLI only for now).
- Multi-tenant isolation.
- Hardware microVM (E2B/Firecracker) isolation.
- Serving models on our own vLLM.
- Driving the user's real production repos.
