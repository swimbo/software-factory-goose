# Phase 6 — Tech Guide

**Status: complete (debated).**

## Objective
Pin the concrete stack with current versions, conventions, dev setup.

## Done
- `tech-guide.md`: Rust 1.90 (edition 2024), Restate `restate-sdk` 0.12.1, Axum 0.8, SQLx 0.8, clap 4, Goose v1.49.0 (headless `goose run`), **Bifrost** gateway (external), open-weights (GLM-5/DeepSeek-V4/MiniMax M2.5).
- Kickoff research (Restate/Goose/gateway) folded into `findings.md`.
- Debate folded into the architecture pass (all volatile tech choices covered); `tech-guide.md` updated with a `## Debate Outcomes` section.

## Verification (Hard Gates)
- [x] Language/runtime pinned (Rust 1.90, edition 2024).
- [x] Frameworks + versions + rationale.
- [x] Dependency list pinned.
- [x] Conventions (rustfmt/clippy, edition 2024).
- [x] Testing stack (unit/integration/CLI/wall-negative).
- [x] Dev env + env contract.
- [x] Build/run commands verbatim.
- [x] CI shape sketch.
- [x] Alignment with architecture components.
- [x] Debate invoked (folded; evidence in consensus-plan.md + transcript).

## Exit signal
Stack pinned; Implementation can scaffold without re-litigating choices.
