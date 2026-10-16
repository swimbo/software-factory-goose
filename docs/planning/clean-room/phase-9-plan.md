# Phase 9 — Implementation

**Status: pending.**

## Objective
Build the working MVP vertical slice: greenfield demo end-to-end (intent → spec → decompose → Goose build in worktree → holdout eval → merge), with the three gates enforced.

## Prerequisites (resolve open items first)
- O1 serving backend (NEEDS_HUMAN_DECISION).
- O4 operator auth/MFA.
- O3 qualifier spec (draft before the qualifier module).

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
- [ ] **T1** Scaffold workspace + `git init` + `cargo` workspaces + CI shape. (blocker for all)
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
- [ ] `cargo test` green; `clippy -D warnings` clean; `fmt --check` clean.
- [ ] Receipt bound to exact git SHA (US-16).
- [ ] Budget cap hard-stops an overage unit (US-9).
- [ ] Negative test: generator cannot read holdout store (US-6/INT-02).

## Exit signal
The factory produces a merged, wall-verified greenfield artifact with gates enforced.
