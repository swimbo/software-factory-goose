# Decisions Index

| Date | Slug | Category | Chosen | Artifact updated |
|------|------|----------|--------|------------------|
| 2026-10-15 | gateway-bifrost | third-party service | Bifrost (waived: externally constrained) | architecture.md, tech-guide.md, gateway.rs, compose.yaml, config.json |
| 2026-10-26 | operator-auth | local transport / privileged authorization | Inert socket spike; user selected separate operator account + action-bound approval, no MFA claim; activation unverified | 2026-10-26-operator-auth.md, 2026-10-26-operator-auth/consensus-plan.md |
| 2026-10-26 | [goose-tool-boundary](2026-10-26-goose-tool-boundary.md) | harness / tool-output contract | Three-reviewer debate: restricted-stock offline spike; no adapter/fork adopted | verification/2026-10-26-goose-protocol.md; brief only |
| 2026-10-27 | [os-supervision-boundary](2026-10-27-os-supervision-boundary.md) | OS runtime / privileged supervision | Three-reviewer research; insufficient evidence for selection, comparative spike | evidence-ledger.md; spike-plan.md |

- 2026-10-28: [Bounded task writer](2026-10-28-structured-task-writer/consensus-plan.md) — three-reviewer consensus for task-only structured writes; pre-live integration/crash/evaluation controls required, no shell relaxation or production activation.

- 2026-10-29: [NUC protected root supervisor](2026-10-29-nuc-root-supervisor/consensus-plan.md) — three-reviewer research/canary/one-round guarded implementation consensus; production recovery/integration gates retained.
