# E2E / Integration Test Plan — Clean-Room Software Factory

This project is a Rust backend/CLI control-plane system with **no browser UI**. Per bo-planning, E2E is **partial** and takes the form of Rust integration tests + CLI tests + a full-loop smoke test, not browser Playwright.

## Test pyramid mapping

| Layer | Tool | Scope |
|-------|------|-------|
| Unit | `#[cfg(test)]` + `tokio::test` + `proptest` | qualifier scoring, gate logic, receipt serialization |
| Integration | Rust integration tests (`tests/`) + `sqlx::test` + Restate in-process | control-plane → worker → evaluator → merge loop |
| CLI | `assert_cmd` | `sfctl` subcommands (submit/inspect/status/approve/deny/stop) |
| Wall (negative) | dedicated evaluator test | proves a scenario body is unreachable by the generator |

## Test inventory (mapped to user stories)

| Test ID | Story | Name | Assertion |
|---------|-------|------|-----------|
| INT-01 | US-1 | submit intent returns a lane | `sfctl submit` → dark|human + score + reason; repeat submit is idempotent |
| INT-02 | US-6 | generator cannot reach holdout scenarios | negative test: a worker process with generator creds cannot read the scenario store (separate uid/no shared mount) |
| INT-03 | US-7 | triple-run 2-of-3 gate | evaluator runs each scenario 3×; a unit clearing <2-of-3 or <90% aggregate is rejected + looped back |
| INT-04 | US-8 | opaque failure feedback | failure message to generator contains no scenario body |
| INT-05 | US-14 | Goose headless contract | `goose run --no-session` returns exit 0 + diff on success, non-zero + receipt on failure |
| INT-06 | US-13 | isolated worktree | each unit gets a fresh worktree; outbound network denied except allowlist; no host secrets present |
| INT-07 | US-16 | receipt binds to revision | receipt records result→claim→stage→exact SHA; a simulated timeout is reconciled |
| INT-08 | US-9 | budget cap stops overage | a unit exceeding per-unit cap fails and loops to human; retries capped at 3 |
| INT-09 | US-11 | first-promotion gate | promotion blocked until `verification.yaml` passes AND human approves; later drift bypasses |
| INT-10 | US-12 | brokered credentials | no secret value in agent context; grants are task-scoped with TTL |
| INT-11 | US-4 | stage observability | every stage transition is an audit event; `sfctl status` lists stage/spend/revision |
| INT-12 | US-3 | codified-knowledge prerequisite | unit against a repo lacking `AGENTS.md` is flagged human-lane |

## Full-loop smoke test (the MVP's proof)

A single end-to-end test (`INT-LOOP`) that submits a tiny greenfield intent (e.g. "build a `hello` CLI that prints 'hello world' and has one passing test") and asserts the full path: intake → qualifier → decompose → Goose build in worktree → holdout eval (2-of-3) → merge. This is the vertical slice proving the factory works, and doubles as CI's step 4.

## Determinism / flakiness notes

- LLM calls are non-deterministic: integration tests use a **recorded/pinned model response** (or a trivial deterministic gateway stub) where possible; the full-loop smoke test uses the real gateway but tolerates retry.
- Restate in-process test harness avoids a live `restate-server` for unit/integration; the smoke test runs a real server.

## Generated test files (inventory, to be created in Phase 9/10)

```
crates/control-plane/tests/intent_flow.rs
crates/control-plane/tests/qualifier.rs
crates/evaluator/tests/wall_isolation.rs   # INT-02 negative test
crates/evaluator/tests/triple_run_gate.rs  # INT-03, INT-04
crates/worker/tests/goose_contract.rs      # INT-05, INT-13/14
crates/sfctl/tests/cli.rs                  # INT-01, INT-09, INT-11
crates/control-plane/tests/full_loop.rs    # INT-LOOP
```
