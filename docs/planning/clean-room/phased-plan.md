# Phased Plan — Clean-Room Software Factory (on Goose)

## Current restart state — 2026-10-26

Resume **late Phase 9**, preserving the existing implementation. Phases 1, 3–6, and applicable CLI Phase 7 are recorded complete; Phases 2 and 8 are skipped with reasons. Phase 4 still carries a story-review confirmation deferred to Delivery. Phases 10–14 remain unfinished. The original environment snapshot and delegation table below are historical. See `restart-audit-2026-10-26.md` for source-backed reconciliation; do not restart Phase 1 or workspace scaffolding.

## Problem Statement

Build a **working MVP of a "dark software factory"** — an autonomous, lights-out software-delivery system in which AI agents take work from intent to production without a human authoring or reviewing the diff. Per the research in `dark-software-factory-report.md`, the factory is *not* the harness: the interesting, must-build-yourself pieces are the **wall** (holdout acceptance scenarios + an isolated evaluator the generator never sees), the **qualifier** (routes each unit into a dark lane or leaves it for humans), and the **gates** (budget, destructive ops, initial production deployment, credential issuance).

The one deliberately *not*-clean-room aspect: the worker agent harness is **Goose** (Block's Apache-2.0 Rust harness) — a lightweight, reviewable, headless foundation — rather than a bespoke agent loop. Everything else follows the report's "Path B" clean-room discipline.

The first working slice is a **greenfield demo**: the factory takes a machine-checkable spec and produces a small project end-to-end (intent → spec → decompose → parallel Goose builders in git worktrees → isolated holdout evaluation → merge), with the three human gates enforced.

## Scope

### IN

- **Control plane (Rust)** — orchestrator owning authoritative state, goal cascade (intent → spec → modules → work packages), the qualifier, and the gates. Does not execute agent code.
- **Durable state on Restate** — append-only, replayable workflow state (claims, leases, attempts, receipts, cooldowns) using Restate as the durable-execution substrate (one self-contained binary, Rust SDK).
- **Execution plane** — bounded Goose workers, each in its own disposable git worktree, deny-by-default network, no inherited host secrets, headless `goose run` invoked as a subprocess with an exit-code + diff contract.
- **Verification plane (the wall)** — isolated evaluator with its own credentials and no access to the generator's prompt/output; holdout scenarios triple-run with a 2-of-3 threshold and a 90% aggregate gate; feeds opaque one-line failures back to generation.
- **Qualifier** — scores each incoming unit (spec/ticket) and routes dark-lane vs human-lane.
- **Three human gates** — (1) initial production deployment / first promotion, (2) budget envelope (agents spend within, only humans raise), (3) credential issuance for anything the agent-mail channel can't self-issue.
- **Model routing via a gateway** — open-weights models (GLM-5 / DeepSeek-V4) served through the **Bifrost** gateway (external, operator-run), cheap-to-cheap and frontier-to-hard routing.
- **Greenfield demo workload** — the first vertical slice produces a small greenfield project from a spec, exercising the whole loop end-to-end.
- **CLI** — a factory CLI (`sfctl`) to submit intents, inspect claims/receipts/stages, and approve/deny gate decisions.
- **Observability** — full traceability of reasoning steps, tool invocations, spend, and stage transitions (the "lights off, nothing unseen" requirement).

### OUT

- **A web/GUI dashboard** — the MVP is CLI + REST; a visual observability dashboard is explicitly deferred (noted as a future phase).
- **Integrating the user's existing "Dev Projects" factory** — the report references it as a conceptual ancestor (goal cascade + receipt-bound claims), but this is a fresh, standalone build. No code is reused or migrated from it.
- **Hardware microVM isolation (E2B/Firecracker)** — the MVP uses git worktrees; microVM isolation is a documented later upgrade, not a Phase 1 deliverable.
- **Self-hosting/ops of the model inference** — the MVP calls a managed gateway; serving GLM-5/DeepSeek on our own vLLM is out of scope for now.
- **Multi-tenant / multi-org support** — single-operator factory for now.
- **Non-greenfield workloads** — driving the user's own real production repos, bugfix backlogs, or migrations is out of scope for the MVP (the qualifier/holdout design assumes a greenfield target first).
- **Frontier/Claude routing** — the MVP is open-weights-only; hybrid frontier routing is a later option, not Phase 1.

## Environment

- **cwd**: `/Users/bo/code/software-factory-goose`
- **git status**: not a git repository (greenfield; will `git init` as a monorepo per decision).
- **Existing files**: only `dark-software-factory-report.md` (37 KB research report) and an empty `.claude/` directory (containing `.cc-writes/`). No prior planning session.
- **Languages detected**: none yet (greenfield). Per user global stack: TypeScript/Rust/Python are the preferred languages; Rust chosen for this control plane.
- **Running services**: none observed.
- **docs/planning/ state**: created this session (was absent).
- **Platform**: macOS (darwin), zsh.

## Constraints

- **Language**: control plane in **Rust** (user decision). Matches Goose (Rust) and the user's preferred backend stack (Axum/SQLx).
- **Harness**: **Goose** as the worker foundation (the one non-clean-room aspect — user decision).
- **Durable substrate**: **Restate** (user decision) — use a durable library rather than hand-rolling replay state.
- **Models**: **open-weights via gateway** (user decision) — no single-vendor frontier lock-in.
- **Workload**: **greenfield demo** for the first slice (user decision).
- **Isolation**: **git worktrees** (user decision), deny-by-default network, no inherited secrets.
- **Repo**: **monorepo** under `/Users/bo/code/software-factory-goose` (user decision).
- **No other hard constraints reported** (no deadline, no compliance regime, no team size, no budget ceiling specified by the user).

## Decisions (locked this session)

| # | Decision | Choice | Notes |
|---|----------|--------|-------|
| D1 | Scope/ambition | Working MVP factory | real end-to-end vertical slice → merged code |
| D2 | Control-plane language | Rust | Axum/SQLx per preferred stack |
| D3 | Durable substrate | Restate | replay-based audit, one binary |
| D4 | Models | Open-weights via gateway | GLM-5/DeepSeek-V4 through **Bifrost** (external, operator-run) |
| D5 | First workload | Greenfield demo | spec → project end-to-end |
| D6 | Repo | Monorepo here | `git init` at `/Users/bo/code/software-factory-goose` |
| D7 | Isolation | Git worktrees | deny-by-default network, no host secrets |

## Phases

Customized from the 14-phase pattern. Conditional phases (UI, browser E2E) are skipped/adapted because this is a Rust backend/CLI control-plane system with no browser UI.

| # | Phase | Applies? | Notes |
|---|-------|----------|-------|
| 1 | Requirements & Discovery | ✅ | this phase (scope, env, decisions) |
| 2 | Pain Point Research | ⚠️ skipped-for-provided-research | `dark-software-factory-report.md` is the user-provided research; kickoff research still done for volatile tech in Phases 5–6 |
| 3 | Data Map | ✅ | factory entities: claims, leases, receipts, specs, modules, work packages, scenarios, budgets, credentials, qualifier scores |
| 4 | User Stories | ✅ | derived from requirements + report findings |
| 5 | Architecture | ✅ | four planes + Restate + Goose + worktrees; **mandatory debate** |
| 6 | Tech Guide | ✅ | Rust/Restate/Goose/gateway versions; **mandatory debate** |
| 7 | UX Planning | ⚠️ partial (CLI ergonomics) | `sfctl` CLI usability; no web UX |
| 8 | UI Planning | ❌ skipped (non-visual) | observability dashboard is OUT; record reason in findings.md |
| 9 | Implementation | ✅ | build the factory, subagents for independent crates |
| 10 | E2E Test Generation | ⚠️ partial (integration tests) | Rust integration tests for the factory loop, not browser Playwright |
| 11 | Testing & Verification | ✅ | run the loop end-to-end, verify gates |
| 11A | Harness Efficiency and Reliability | ✅ | required before Delivery; implementation incomplete, live paired runs 0/120; see phase-11a-plan.md; candidate disabled |
| 12 | Delivery | ✅ | user verification; blocked until Phase 11A live paired acceptance passes |
| 13 | Plan Gap Audit | ✅ | diff implementation vs plan |
| 14 | Fix All Gaps | ✅ | close gaps in severity order |

## Delegated Work

| Task | Agent Type | Status | Result |
|------|-----------|--------|--------|
| Research Restate Rust SDK (current) | general-purpose | in_progress | → tech-guide.md |
| Research Goose headless/recipes/MCP/worktree | general-purpose | in_progress | → tech-guide.md |
| Research gateway + open-weights serving | general-purpose | in_progress | → tech-guide.md |

## Current delegated work — 2026-10-26 continuation

The earlier research-agent table is historical; this is the current implementation delegation.

| Area | Agent | Status | Evidence / boundary |
| --- | --- | --- | --- |
| Worker supervision/policy/masking, setup, evaluator pre-filter | worker | component fixes and pinned Goose audit complete; tool-boundary decision pending | execution tests, setup fixtures, evaluator9 tests; live worker disabled |
| Exact revision evaluator, operator transport, story audit | verifier | component fixes and private-ingress research complete | evaluator integration fixtures, transport6 tests, preliminary story matrix |
| Gateway/projection, approval journal, claim/lease journal | durability | bounded journal/outbox components and disposable DB fixture verified | scoped Restate/lease13 tests, disposable Postgres fixture; live replay unproved |
| Intake/status/gate safety, integration review and planning reconciliation | root | in progress | route/qualifier regressions and current gap register |

Continue late Phase9 at the unresolved runtime boundaries, then the remaining gates. O4 is resolved to separate local operator and action-bound approval without MFA. The proposed Goose boundary debate is a new contract issue supported by pinned source evidence, not a restart of O4 or Phase1.
