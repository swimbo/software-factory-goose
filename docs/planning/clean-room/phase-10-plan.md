# Phase 10 — CLI and integration verification

Status: in progress as test inventory and component tests; dependent on Phase 9 runtime wiring. Browser/UI tests are not applicable.

The existing `e2e-tests.md` remains the scenario inventory, interpreted through consensus R2/R11 (model votes are a pre-filter; deterministic verification and human promotion remain required). `verification/2026-10-26-story-coverage.md` maps every scenario to current evidence and gaps.

- [x] Inventory actual Rust suites and CLI fixture tests; distinguish component, OS fixture, database fixture and live runtime proof.
- [x] Add negative regression tests for fabricated approvals/merge success, invalid budget/qualifier values, malformed receipts, callback stage skipping, command bypasses, unmasked subprocess output, actual verifier compile/test failures, exact revision drift and CLI failure exit status.
- [x] Add action-bound approval and kernel Unix-peer transport tests under the selected O4 contract.
- [ ] Generate/run missing real integration scenarios INT-01 through INT-12, including durable idempotence/recovery, generator holdout denial, real Goose protocol, mandatory gateway cutoff, broker TTL and auditable human promotion.
- [ ] Execute INT-LOOP against an isolated provisioned factory with external Bifrost and real human approval; record exact source revision and artifact SHA.
- [x] Retain the Cargo test runner and documented CI shape. `tech-guide.md` explicitly puts CI implementation out of the MVP; do not invent an executable-CI blocker.
- [ ] Verify every planned scenario has a discoverable passing specification. Do not use ignored placeholder tests to count missing scenarios as generated coverage.

No Phase 10 completion is claimed. A passing Cargo suite only describes the specifications that exist; it cannot stand in for missing runtime scenarios.

## Verification (original gates retained)
- [ ] Every P0 story has an integration test mapped to it.
- [ ] INT-02 (negative: generator can't reach holdout store) passes.
- [ ] INT-LOOP passes against a real gateway + real Goose.

## Exit signal
The loop is verifiable by automated tests.
