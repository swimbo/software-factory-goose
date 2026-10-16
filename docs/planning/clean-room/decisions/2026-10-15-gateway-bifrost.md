# Decision — Model gateway: Bifrost

- **Date**: 2026-10-15
- **Category**: third-party API / service (volatile)
- **Status**: decided
- **Artifacts updated**: `architecture.md`, `tech-guide.md`, `findings.md`, `phased-plan.md`, `phase-6-plan.md`, `phase-9-plan.md`, `clean-room/{compose.yaml,setup.sh,gateway/config.json,crates/control-plane/src/gateway.rs}`

## Decision

Use **Bifrost** (Maxim AI) as the factory's model gateway (the credential broker + budget choke point), instead of the earlier **LiteLLM** default.

## Options considered

1. **LiteLLM (Rust core)** — the earlier default. Market leader, OpenAI-compatible, virtual keys + budget caps, self-hostable. Chosen initially because it has the cleanest `--config` self-host story.
2. **Bifrost (Maxim AI)** — Go single-binary, OpenAI-compatible, hierarchical budgets, immutable audit logs, governance API. **Chosen.**
3. **OpenRouter (hosted)** — rejected: third-party data path, per-token markup, no self-host.

## Rationale

The operator **already runs Bifrost on their network**. That is an external infrastructure constraint, not a from-scratch choice — a "both fit" comparison is moot when one is already operated. Bifrost also has the stronger audit story (immutable audit logs) the factory's observability posture wants.

## Debate waiver (Mode B)

The bo-planning skill triggers a Mode B debate on volatile third-party-service choices. It is **waived** here because the choice is externally constrained (the operator's existing infrastructure) and cannot be overridden by argument — the practical answer is fixed. This is a `complete_with_override`-style waiver, reason recorded. (Contrast: the upstream decision *was* debated — the architecture debate produced R7, the default-deny cumulative budget requirement, which holds regardless of which gateway realizes it.)

## Consequences (folded into code)

- Inference auth: Bifrost virtual keys go in the **`x-bf-vk`** header, not `Authorization: Bearer`.
- Budget read: **`GET /api/governance/virtual-keys`** (management bearer), remaining = `max_limit − current_usage`.
- Config format: **JSON** (`gateway/config.json`), replacing the LiteLLM YAML.
- Not containerized: Bifrost is external; `compose.yaml` keeps only `restate` + `postgres`.

## Unresolved concerns

- Bifrost governance API shape may differ slightly by version (v1.5.0 moved `budget` → `budgets[]`); verify against the operator's Bifrost version.
- The `remaining_budget()` parse assumes the `budgets[]` envelope; adjust if the operator's instance returns a different shape.
