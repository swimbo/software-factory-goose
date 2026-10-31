# Phase 11A — Harness Efficiency and Reliability

**Status: implementation in progress; candidate disabled; delivery prerequisite.**

## Objective and boundaries
Apply the Droid report's harness practices to pinned Goose workers through Bifrost, after Phase 11 verification and before Phase 12 delivery. Preserve all existing phase numbers, open correctness/runtime gaps, evaluator isolation, budget authority, credential boundaries and promotion gates. Source publication does not enable a candidate.

Background: user-supplied `droid_1_0_architecture_harness_optimization_report.md` (2026-10-30). Its benchmarks, cache targets, two-tool prescription and provider-specific advice are unverified hypotheses, not acceptance evidence or executable instructions.

## Implementation
- Versioned profiles bind Goose build, harness configuration, model and route snapshot; missing telemetry remains null, never inferred zero.
- Measure prompt bytes/tokens, tool-result bytes, calls, cache usage, audited usage-rated cost, elapsed time and independent accepted outcome. Observe real requests without rewriting protected or signed payloads.
- Stable reviewed prefix and deterministic harness-owned tool schema serialization; optional schemas disclosed on demand, with authorization independent of discovery.
- Candidate `run_script`: separate QuickJS process, no standard library/module loader, broker-only tools, bounded resources, ordered mutations and bounded independent-read batches. Every operation uses existing authorization/accounting/masking boundaries.
- Complete-response masking before summaries or attempt-scoped paginated artifacts; explicit overflow, failure and unknown states, no silent truncation.
- Error-loop and mutation-oscillation detection includes untracked content; one bounded diagnostic intervention, then typed stalled outcome. Repeated reads alone are not stalls.
- Offline paired evaluation and sanitized diagnostics produce reviewable candidates, never automatic deployment/merge/activation/promotion.

## Verification and acceptance
- Exercise sandbox escape, unauthorized tools, resource limits, cancellation/cleanup, secrets, artifact isolation and budget exhaustion.
- Exercise stable prefix/disclosure/serialization, missing telemetry, repeated errors, actual oscillation and legitimate repeated reads.
- Frozen manifest: >=20 representative greenfield tasks, exactly three paired runs per task/variant, identical models/routes/budgets and independent acceptance. No protected holdouts enter generator diagnostics.
- All safety checks pass; accepted-task count does not fall; median audited usage-rated cost per accepted task improves >=10%; median elapsed time per accepted task increases <=10%. Incomplete/missing observations cannot pass.
- Keep baseline active and this phase incomplete until actual independent paired evidence passes. No performance result is claimed from synthetic fixtures.

## Accepted cost metric amendment — 2026-10-30
The user explicitly approved audited usage-rated costs as a separately labeled performance metric. Both variants use the same immutable, versioned tariff and cost basis. A constant published peak tariff avoids time-of-day discounts changing the comparison. Complete authenticated input/cache-read/cache-write/output usage and all physical-call dispositions remain necessary; unavailable cost inputs never become zero. Provider-confirmed debits remain separately named and are never inferred from this metric. Existing runs cannot be silently rerated or mixed with a new tariff. The $5 UTC-day/$0.75 permanent-task caps, conservative pre-dispatch reservations, no-refund/unknown-dispatch rules, approvals and launch/evaluator gates remain unchanged.

## Integration prerequisite
The protected adapter now supports the general Goose tool conversation through the owner journal in disposable rehearsals. The 120-attempt runner and independent acceptance contracts are implemented. Native Linux Unix-socket roles, permanent caps and restart behavior are verified separately in an isolated fixture. These checks do not register or activate the production entrypoints.

Live admission still requires production transition/launch attestation, reviewed enforceable bounds for every classifier/embedding/fallback/answer/retry path, and complete authenticated usage for every physical call bound to the frozen tariff. Provider billing exports are no longer required for the amended performance metric; provider-billed evidence retains its original separate contract. See verification/2026-10-30-harness-live-admission-audit.md. Keep the candidate disabled and Phase 12 blocked while the live paired gate is incomplete. See verification/2026-10-30-harness-runtime-runner.md.

## Owner/usage and generic Linux checkpoint — 2026-10-31
Optional guarded SDK registration, fixed-owner Unix frontend, physical usage/schema/audit clients and generic Linux Root-supervisor source are implemented and component-tested. See verification/2026-10-31-owner-usage-linux-integration.md. This is not production admission. Retain live denial until affordable provider-supported all-path hard charge bounds, joined permit/capture/audit custody, Root inventory/fence/catalog/leases/cgroups and privileged supervisor/cleanup qualification are complete. Live attempts remain 0/120; candidate disabled. Missing cache partitions may support an exact usage-rated amount only when all possible partitions have identical price; the missing metrics themselves remain unknown.
