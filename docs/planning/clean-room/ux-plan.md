# UX Plan — `sfctl` CLI (partial)

This project is a Rust backend/CLI control-plane system with **no web UI** (observability dashboard is OUT of scope). UX planning is therefore **partial** and focuses on the `sfctl` CLI ergonomics — the only human-facing surface for the MVP. Per bo-planning, API/backend services get "Partial (API ergonomics)" treatment.

## Users

- **Intent author** — a human describing work in plain English, expecting a quick lane answer.
- **Factory operator** — a human at the three gates (first promotion, budget, credentials), inspecting claims/receipts and approving/denying.

## CLI usability principles (12-Factor CLI / Heroku)

1. **Predictable subcommands** — `sfctl submit`, `sfctl inspect`, `sfctl status`, `sfctl approve`, `sfctl deny`, `sfctl budget`, `sfctl logs`. No positional ambiguity.
2. **Idempotent + safe by default** — every destructive action (`approve` on a promotion, `deny`) is explicit and requires confirmation unless `--yes`; nothing destructive is silent.
3. **Machine-readable output** — `--json` on every command for scripting; human-readable tables by default.
4. **One-line exit codes** — 0 on success, non-zero on any failure; errors go to stderr, data to stdout.
5. **`--help` on every surface** — no command is a mystery.

## Core flows

### Submit an intent
```
sfctl submit --title "Add X" --description "..." --acceptance "..." [--repo <path>]
```
→ returns lane (dark|human), score, reason. Idempotent: re-submitting the same intent returns the existing record (no duplicate).

### Inspect qualifier reasoning
```
sfctl inspect <intent-id>      # factors + lane + reason
sfctl inspect <intent-id> --json
```

### Watch a unit through stages
```
sfctl status                    # active work packages, stage, worker, spend, revision
sfctl status <work-package-id>  # detailed receipts + evaluation runs
```

### Gate approvals
```
sfctl approve <promotion-id>    # first-production promotion (Gate 1) — requires --yes
sfctl approve <grant-id>        # privileged credential (Gate 3)
sfctl budget raise --to <usd>   # Gate 2 — human only
sfctl deny <id> --reason "..."
```

## Error handling strategy

- **Every failure is actionable** — messages name the entity and the state that failed, never a raw stack trace.
- **Opaque wall failures stay opaque to the generator**, but the *operator* sees the full scenario result (the wall's opacity is a generator-only constraint, not an operator constraint).
- **Idempotency keys** for `submit` and `approve` to survive retries without double-effects.
- **Human kill switch** is always reachable — `sfctl stop <work-package-id>` cancels a lease immediately.

## Accessibility & non-functional

- Color-blind-safe status indicators (stage shown as text + icon, not color alone).
- All output streams (`--json`) are parseable by `jq` for automation.
- Spend and stage transitions are always visible (observability requirement: "lights off, nothing unseen").

## Dark-pattern audit

- **No** hidden auto-approval — gates are explicit, and the operator is never defaulted into "yes."
- **No** obscured spend — every `status` shows current spend vs. envelope.
- **No** silent retries that bill — retry count and spend are surfaced, capped at 3/spec.

## Out of scope (deferred)

- Web/GUI dashboard (future phase).
- Interactive TUI (plain CLI for MVP).
