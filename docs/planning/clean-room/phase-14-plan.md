# Phase 14 — Fix All Gaps

**Status: pending.**

## Objective
Close `plan-gaps.md` items in severity order (`blocker` → `major` → `minor` → `nit`).

## Task checklist
- [ ] For each non-`wont_fix` gap: implement fix, re-run relevant tests, flip status to `fixed`.
- [ ] Re-verify consensus R1–R12 are satisfied post-fix.

## Verification
- [ ] `plan-gaps.md` shows zero open items (all `fixed` or `wont_fix`).
- [ ] Full test suite green after fixes.

## Exit signal
The factory matches the plan, with no open gaps.
