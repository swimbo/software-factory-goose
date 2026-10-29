# Phase 11 — Testing & Verification

**Status: local component checks passing; runtime acceptance pending (Phase 9 remains open).**

## Objective
Run the full suite, verify requirements met, verify the gates actually gate.

## Task checklist
- [x] Current locked/offline all-target/all-feature workspace suite: 408 passed, 0 failed, 2 runtime-dependent cases ignored by that command. Both were subsequently exercised in the disposable native Restate/PostgreSQL replay and diagnostic projection fixtures. Missing connected runtime scenarios remain open below. See `verification/2026-10-28-runtime-verification.md`.
- [x] All-target/all-feature `cargo clippy -- -D warnings`, `cargo fmt --all -- --check`, and all-feature build passed; saved final logs in `verification/`.
- [ ] INT-LOOP end-to-end pass.
- [ ] Gate-verification tests: first-promotion blocks without human approval; budget-raise blocks below threshold; privileged credential blocks without approval.
- [ ] Kill-switch test: `sfctl stop` terminates the whole process group.
- [ ] Wall-isolation test (generator can't read holdout store).

## Verification
- [ ] All P0 acceptance criteria demonstrated, not assumed.
- [ ] Failures logged in `progress.md`; 3-strike protocol applied on any flaky test.

## Exit signal
Every in-scope outcome is proven by a passing test.
