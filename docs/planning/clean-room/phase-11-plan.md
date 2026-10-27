# Phase 11 — Testing & Verification

**Status: local component checks passing; runtime acceptance pending (Phase 9 remains open).**

## Objective
Run the full suite, verify requirements met, verify the gates actually gate.

## Task checklist
- [x] Existing unit/integration/example-guard suite: 135 passed, 0 failed, 0 ignored with all targets/features. Missing runtime scenarios remain open below.
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
