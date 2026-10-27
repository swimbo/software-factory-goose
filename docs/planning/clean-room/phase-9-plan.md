# Phase 9 — Implementation

**Status: in progress — existing implementation; resume with remaining gaps and runtime verification.**

Restart audit (2026-10-26): the checklist below predates committed implementation and is not a reliable indicator of absent code. Do not restart scaffolding. See `restart-audit-2026-10-26.md` for current evidence and remaining gaps.

## Objective
Build the working MVP vertical slice: greenfield demo end-to-end (intent → spec → decompose → Goose build in worktree → holdout eval → merge), with the three gates enforced.

## Prerequisites (resolve open items first)
- O1 resolved: hosted open-weights through the operator's external Bifrost gateway.
- O4 resolved by user on 2026-10-26: separate local operator account and action-bound approval channel; **no MFA claim**. See `decisions/2026-10-26-operator-auth.md`. Runtime provisioning and per-request authority wiring remain implementation/verification work.
- O3 scoring contract implemented; calibration and intake feature extraction remain provisional.

## Workspace (monorepo, `clean-room/`)
```
crates/
  control-plane/   # Rust + Axum + restate-sdk + SQLx (orchestrator, qualifier, gates)
  execution/       # worker daemon: subscribes Claim/Lease, runs goose in sandbox
  evaluator/       # the wall: isolated, holdout scenarios, deterministic checks
  sfctl/           # clap CLI
  shared/          # Receipt/Claim/CredentialGrant types, outbox schema
```

## Task checklist (subagent delegation plan)
- [x] **T1** Scaffold workspace + `git init` + `cargo` workspaces + CI shape. Existing committed five-crate workspace, lockfile and Git repository verified; `tech-guide.md > CI shape` explicitly scopes CI itself out of the MVP. No re-scaffolding or CI-provider adoption needed.
- [ ] **T2** `shared`: typed `Receipt`/`Claim`/`CredentialGrant` + JSON schema (R6, blind-spot contract schema).
- [ ] **T3** Control plane: Restate workflow (goal cascade + claim/lease/attempt/cooldown + budget state object, R3/R7).
- [ ] **T4** Control plane: Postgres read projection via idempotent outbox (R3).
- [ ] **T5** Qualifier module (per O3 spec) + lane routing.
- [ ] **T6** Execution plane: worker daemon subscribing Claim/Lease; Goose headless spawn with typed Receipt parse, `kill -pgid`, distinct uid/env (R4/R5/R6/R9/R10).
- [ ] **T7** Evaluator: holdout store (uid + Seatbelt, R1), triple-run pre-filter + deterministic verifier (R2/R11).
- [ ] **T8** Gateway wiring: **Bifrost** default-deny cumulative budget (R7) + git deploy-key broker (R8).
- [ ] **T9** Gates: first-promotion, budget-raise, credential issuance + out-of-band brake (R9).
- [ ] **T10** `sfctl` CLI (submit/inspect/status/approve/deny/stop/budget).

## Delegation
T2/T3/T4/T5 (shared+control-plane) are interdependent → sequence; T6 (execution), T7 (evaluator), T8 (gateway), T10 (cli) are independent once T2 lands → **parallel subagents**.

## Verification (Hard Gates)
- [ ] Full loop runs: greenfield intent → merged diff + wall pass (INT-LOOP).
- [x] Local component gate: all-target/all-feature locked offline suite **288 passed, 0 failed, 0 ignored**; Clippy with warnings denied, formatting and build passed. See `verification/2026-10-27-*-continuation.log`. This does not close INT-LOOP or live safety gates.
- [ ] Receipt bound to exact git SHA (US-16).
- [ ] Budget cap hard-stops an overage unit (US-9).
- [ ] Negative test: generator cannot read holdout store (US-6/INT-02).

## Exit signal
The factory produces a merged, wall-verified greenfield artifact with gates enforced.
