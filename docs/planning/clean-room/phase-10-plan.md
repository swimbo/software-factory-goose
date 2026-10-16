# Phase 10 — E2E / Integration Test Generation

**Status: pending (partial — integration tests, not browser Playwright).**

## Objective
Generate integration tests for the factory loop per `e2e-tests.md`.

## Task checklist
- [ ] INT-01…INT-12 per the test inventory in `e2e-tests.md`.
- [ ] INT-LOOP full-loop smoke test (the vertical-slice proof).
- [ ] `assert_cmd` CLI tests for `sfctl`.

## Verification
- [ ] Every P0 story has an integration test mapped to it.
- [ ] INT-02 (negative: generator can't reach holdout store) passes.
- [ ] INT-LOOP passes against a real gateway + real Goose.

## Exit signal
The loop is verifiable by automated tests.
