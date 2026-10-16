# Phase 7 — UX Planning

**Status: complete (partial — CLI ergonomics only).**

## Scope
Backend/CLI control-plane system, no web UI. UX = `sfctl` CLI ergonomics only.

## Done
- `ux-plan.md`: CLI principles (12-Factor/Heroku), core flows (submit/inspect/status/approve/deny/budget/stop), error-handling strategy, dark-pattern audit.

## Verification
- [x] User flows for the 3 gates + intake + observability.
- [x] Error-handling strategy (opaque-to-generator vs full-to-operator).
- [x] Dark-pattern audit (no hidden auto-approval, no obscured spend).

## Exit signal
`sfctl` surface specified; no web UX needed.
