# Progress

Session log, test results, error log.

## Session start
- **2026-10-13** — Planning a clean-room software factory on Goose, per `dark-software-factory-report.md`.
- Environment: `/Users/bo/code/software-factory` greenfield (not a git repo).
- Planning artifacts live in `docs/planning/clean-room/` (user-directed path).

## Decisions (locked)
D1 Working MVP factory · D2 Rust · D3 Restate · D4 open-weights via gateway · D5 greenfield demo · D6 monorepo (clean-room subproject) · D7 git worktrees. User confirmed 2026-10-13.

## Phase status
- Phase 1 Requirements: **complete**
- Phase 2 Pain Point Research: **skipped** (user-provided research)
- Phase 3 Data Map: **complete**
- Phase 4 User Stories: **complete** (16 stories)
- Phase 5 Architecture: **complete** (5-persona debate → consensus R1–R12)
- Phase 6 Tech Guide: **complete** (debate folded in)
- Phase 7 UX (CLI): **complete** (partial)
- Phase 8 UI: **skipped** (non-visual)
- Phases 9–14: **in progress** — Phase 9 implementation started (code written; build blocked by sandbox crates.io).

## Implementation state (Phase 9, in progress)
Workspace scaffolded at `clean-room/` (5 crates). Code written:
- `crates/shared` — typed Receipt/Claim/CredentialGrant/QualifierDecision/etc. (+ tests)
- `crates/control-plane` — qualifier (pure, + tests), gates (pure, + tests), Axum HTTP API
- `crates/execution` — Goose headless runner (typed Receipt, kill -pgid)
- `crates/evaluator` — deterministic verifier + holdout 2-of-3/90% gate (+ tests)
- `crates/sfctl` — clap CLI (submit/inspect/status/approve/deny/budget/stop)

Not yet wired: Restate workflow (durability), Postgres outbox projection, gateway budget wiring, full-loop integration. `git init` blocked by sandbox (manual step).

## Errors
- **Sandbox blocks crates.io** (`index.crates.io:443` denied, strict allowlist — `allowed_domains` cannot widen). `cargo build`/`cargo test` cannot fetch deps in this session. Build must run outside the sandbox (see command below).

## Testing (Phase 9/11 — verification)
- **31 tests pass, `cargo clippy` clean (0 warnings).** Breakdown:
  - control-plane lib: 18 (qualifier 4, gates 5, gateway 3, state 6)
  - control-plane bin: 2 (HTTP integration — submit→dark-lane, inspect round-trip)
  - evaluator: 5 (holdout gate, secret-scan, deterministic verifier)
  - execution: 3 (turn-count parse, kill-pgid, receipt)
  - shared: 3 (receipt round-trip)
- Fixed during testing: `ExitStatus::signal()` import, clap `env` feature, sfctl partial-move, and a **qualifier logic bug** (missing knowledge now a hard gate; weights rebalanced so high blast-radius routes human).
- Refactored control-plane into lib + bin (eliminated dead-code warnings).

## Remaining (integration layer, needs live system)
- Restate workflow (`workflow.rs`) — **compiles** against the real SDK (verified `--features restate`). Corrected API: macros on impl block, contexts take `'_`, `HandlerResult`, `ctx.promise`/`resolve_promise`.
- Postgres outbox relay — `projection.rs` written (migrate + idempotent upserts), pool wired.
- Gateway client — `GatewayClient` written (chat + default-deny budget read).
- Full-loop wiring — control-plane serves Restate (:9080) + Axum (:8080); execution plane's `resolve_workflow` POSTs the receipt to the workflow's `complete`.

## To actually run the loop (needs live services)
- `restate-server` (Docker Compose), running Postgres, the operator's **Bifrost** gateway (external), and registering the workflow endpoint. The code is wired; standing up these services + a smoke run is the final runtime step.

## Decision — Bifrost gateway (2026-10-15)
Switched the model gateway from the LiteLLM default to **Bifrost** (operator runs it on their network). Code: `gateway.rs` now uses the `x-bf-vk` header for chat + the governance API for budget reads; config is `gateway/config.json` (JSON); `compose.yaml` drops the gateway container. Debate waived (externally constrained) — see `decisions/2026-10-15-gateway-bifrost.md`. Port map: Restate host `:8090`, Axum `:8081`, SDK `:9080`, Bifrost external `:8080`.

## Research delegations (all complete)
- Restate Rust SDK (restate-sdk 0.12.1, embedded log + RocksDB + S3, MSRV 1.90) ✓
- Goose (aaif-goose/goose v1.49.0, `goose run --no-session`, recipes YAML, engine:openai providers, no native worktree) ✓
- Gateway (LiteLLM Rust core / Bifrost; GLM-5/DeepSeek-V4/MiniMax M2.5 ~15–20× cheaper) ✓

## Debate (complete)
5 personas → moderator synthesis (12 contested, 7 HIGH) → 1 response round → consensus. Artifacts: `consensus-plan.md`, `debate-transcript.md`. architecture.md + tech-guide.md updated with `## Debate Outcomes`.

## Open items (for user)
- **O1 serving backend — NEEDS_HUMAN_DECISION** (hosted open-weights endpoints vs self-hosted GPUs).
- O2 gate sample size (cost-bounded MVP resolution).
- O3 qualifier spec (follow-on doc before Phase 9).
- O4 operator auth/MFA.
- O5 scenario authoring/coverage/drift.
- O6 supply-chain (generator as attacker).

## Improvements workstream (2026-10-15)
New planning effort: fold 4 best practices from the `code-machine` analysis into the factory as **R13–R16** (scope confirmed: all 4, clean-room only; R13 as both layers; R16 Rust-native, no Python).
- Artifacts: `improvements-plan.md` (new, the phase plan), `consensus-plan.md` (+R13–R16), `findings.md` (+code-machine analysis), `user-stories.md` (+US-17…US-20), `architecture.md` (+components 7–10), `tech-guide.md` (+deps), `data-map.md` (+entities 16–20).
- Decisions: R16 backend = **tree-sitter + pgvector on the existing Postgres** (recommended; reuses infra, no Python sidecar). R13 = shim + OS backstop.

## Errors
- *(none)*
