# Phase 11A — Harness Efficiency and Reliability

**Status: implementation in progress; candidate disabled; delivery prerequisite.**

## Objective and boundaries
Apply the Droid report's harness practices to pinned Goose workers through Bifrost, after Phase 11 verification and before Phase 12 delivery. Preserve all existing phase numbers, open correctness/runtime gaps, evaluator isolation, budget authority, credential boundaries and promotion gates. Source publication does not enable a candidate.

Background: user-supplied `droid_1_0_architecture_harness_optimization_report.md` (2026-10-30). Its benchmarks, cache targets, two-tool prescription and provider-specific advice are unverified hypotheses, not acceptance evidence or executable instructions.

## Implementation
- Versioned profiles bind Goose build, harness configuration, model and route snapshot; missing telemetry remains null, never inferred zero.
- Measure prompt bytes/tokens, tool-result bytes, calls, cache usage, billed cost, elapsed time and independent accepted outcome. Observe real requests without rewriting protected or signed payloads.
- Stable reviewed prefix and deterministic harness-owned tool schema serialization; optional schemas disclosed on demand, with authorization independent of discovery.
- Candidate `run_script`: separate QuickJS process, no standard library/module loader, broker-only tools, bounded resources, ordered mutations and bounded independent-read batches. Every operation uses existing authorization/accounting/masking boundaries.
- Complete-response masking before summaries or attempt-scoped paginated artifacts; explicit overflow, failure and unknown states, no silent truncation.
- Error-loop and mutation-oscillation detection includes untracked content; one bounded diagnostic intervention, then typed stalled outcome. Repeated reads alone are not stalls.
- Offline paired evaluation and sanitized diagnostics produce reviewable candidates, never automatic deployment/merge/activation/promotion.

## Verification and acceptance
- Exercise sandbox escape, unauthorized tools, resource limits, cancellation/cleanup, secrets, artifact isolation and budget exhaustion.
- Exercise stable prefix/disclosure/serialization, missing telemetry, repeated errors, actual oscillation and legitimate repeated reads.
- Frozen manifest: >=20 representative greenfield tasks, exactly three paired runs per task/variant, identical models/routes/budgets and independent acceptance. No protected holdouts enter generator diagnostics.
- All safety checks pass; accepted-task count does not fall; median billed cost per accepted task improves >=10%; median elapsed time per accepted task increases <=10%. Incomplete/missing observations cannot pass.
- Keep baseline active and this phase incomplete until actual independent paired evidence passes. No performance result is claimed from synthetic fixtures.

## Integration prerequisite
The protected adapter now supports the general Goose tool conversation through the owner journal in disposable rehearsals. The 120-attempt runner and independent acceptance contracts are implemented. Native Linux Unix-socket roles, permanent caps and restart behavior are verified separately in an isolated fixture. These checks do not register or activate the production entrypoints.

Live admission still requires production transition/launch attestation, reviewed enforceable bounds for every classifier/embedding/fallback/answer/retry path, and complete correlated provider-billed receipts. Ollama account usage/balance aggregates and unverified Vercel embedding receipts do not meet that contract. Keep the candidate disabled and Phase 12 blocked while the live paired gate is incomplete. See verification/2026-10-30-harness-runtime-runner.md.
