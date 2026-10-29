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

## Late Phase 9 — real uncapped Goose generation/evaluation, 2026-10-28

Continued from 1ad8838 without restarting Phase 1. User explicitly waived every monetary cap for this named INT-LOOP, including the $0.75 task ledger; no Bifrost key/router settings were changed. Actual NUC generation10 completed Goose → UID-gated host relay → existing Bifrost model:auto → fixed structured two-file writer → exact continuation. Both routed observations were deepseek-v4.1-flash:1017, selected by the existing router. Its durable fence is done, manager recovery verified, both owned roots removed, exact worker slice empty, original inert create guard intact and Docker/Hermes services active.

Candidate b468844bcfb6a3ec4e337efe8e2e6d45cdedbd90 (baseline40b84df26736e522e0e98180d836b24e021d788b) passed 21/21 independent isolated executions and candidate tests; evaluated/committed blobs match. A second exact-blob run passed21/21 after enforcing the >=90% aggregate gate. The accepted ref remains absent; proposed promotion is prepared, not approved/executed. Evidence: verification/2026-10-28-real-int-loop/ and verification/2026-10-28-runtime-verification.md.

Errors/mutations: earlier distinct attempts remain fenced and retained, never reset. Fixes include held-open nc stdin, strict complete HTTP framing, coherent bounded response sizes/incremental parsing, observed bounded Bifrost reasoning_details/SSE comments, and exact Goose per-delta reasoning reconstruction in the continuation. Retained response diagnostics were reparsed offline before fresh attempts. A reference evaluator exposed its Python PATH assumption; fixed absolute contained interpreter and then reference/actual runs passed. Independent audit found missing all-runs aggregate enforcement; collector/finalizer and negative controls fixed, actual exact blobs revalidated. Full chronology: verification/2026-10-28-live-intloop-attempt.md. Provider captures remain sensitive host-only0600/0700 data; literal credential-byte checks are not general sanitization.

## Phase 11 Results — current component evidence, 2026-10-28

Locked/offline all-target/all-feature Rust workspace:408 passed,0failed,2ignored; both runtime-dependent cases subsequently exercised through the full disposable native Restate/Postgres replay and diagnostic projection. Formatting, strict workspace Clippy, doctests and all examples build passed. Final Python discovery:111 passed,0failed. Raw logs: verification/2026-10-28-uncapped-*.log and final-evaluator-controls.log. No UI exists; UI design/accessibility gate is not applicable. These results do not certify complete P0 acceptance, test adequacy/mutation coverage or enterprise readiness.

## Current blocking boundary and gate reconciliation — 2026-10-28

Independent story, runtime/architecture and NUC deployment reviews reconcile current gaps in verification/2026-10-28-late-phase9-boundary-audit.md. G-01–G-11 remain open; no full INT-LOOP or production activation claim. Diagnostic entrypoints, authoritative intake/cascade/queue/launcher/wall/promotion integration and separate operator provisioning remain incomplete. Docker live restore is disabled; Docker-only guardian/operator fixtures do not establish daemon-independent stop. Noninteractive sudo unavailable and no host account exists for fixture UID1002. No shared service/account/data was modified, restarted or migrated.

A human choice is pending on the explicit host-administration mechanism in deployment/nuc-administrative-boundary.md. Existing Docker fixture permission is not silently treated as approval to modify the host OS. No root installer ran. Existing pre-session dirty phase1/phased-plan/progress edits and root README are preserved outside these commits.

Canonical done-means-done checklists were located in bo-planner0.2.0/done-means-done. This is a blocking-state reconciliation, not the final all-phase audit:

| Phase | Gate | Status | Evidence |
| --- | --- | --- | --- |
| 9 | Scope fidelity / every P0 user story fulfilled | fail | independent boundary audit; G-01–G-11 |
| 9 | Architecture and supported production deployment | fail | diagnostic/fixture entrypoints; unprovisioned roles/independent supervisor |
| 9/11 | Build, lint, typed compilation and component tests | pass | uncapped workspace/replay/projection/examples/Python logs |
| 11 | Every P0 live acceptance / full connected E2E | missing | generation/evaluation slice passes; intake→merge loop remains incomplete |
| 11.6 | Enterprise A/B assessment | missing | profile/must-pass selection and assessment not reached |
| 12 | All earlier phases closed / explicit delivery sign-off | missing | no delivery approval requested or inferred |
| 13 | Full artifact coverage and user-approved gap severities | missing | current audit preliminary; no user certification |
| 14 | Zero open blocker/major gaps and final sign-off | fail | G-01–G-11 retained, no waiver |

Continue from late Phase9 operating boundaries, preserving every unknown attempt and the scoped candidate. Do not regenerate the successful candidate or replay a prior fence merely to resume.
