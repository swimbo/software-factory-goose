# Decision brief: mandatory Goose tool boundary and truthful completion

Status: proposed; debate confirmation pending. Scope: late Phase 9, existing Goose worker and R6/R13/R14 contracts. No harness replacement or global installation is authorized by this brief.

## Problem and evidence

The installed Goose reports1.0.16 and lacks planned headless flags. The official1.49.0 macOS arm64 release was downloaded separately, matched its published SHA256, and passed scrubbed-environment version/help probes. Inspection of that exact release found that CLI JSON emits `metadata.status = completed` even after stream errors/cancellation. Its optional hooks are absent by default, subagents disable hooks, and post-tool hooks do not replace the tool result. Therefore neither a JSON status field nor merely configuring hooks establishes the planned completion or pre-model masking boundary.

Full provenance, pinned source lines and limitations: `../verification/2026-10-26-goose-protocol.md` (being finalized). Existing live execution remains blocked. No model calls or global Goose/configuration changes were performed.

## Decision questions

1. Can a restricted Goose configuration, protected from the generator, expose only factory-owned MCP tools and prevent builtin/subagent/extension bypass? What exact release capabilities prove this?
2. Should a narrowly maintained Goose patch/library integration instead enforce policy and masking inside every tool-result path? What maintenance and verification burden does this introduce?
3. What independently observed termination/cost/artifact evidence may produce a typed receipt when upstream JSON status is not a reliable success signal? Retain exact-SHA wall verification and human promotion; never infer success solely from exit0 or stdout.
4. What smallest offline canary proves forbidden commands never execute and synthetic secrets never reach a recording model endpoint, including error, nested/subagent and cancellation paths?

## Options to examine

- Restricted, factory-owned tool transport plus OS backstop, with all other tool surfaces disabled and proven inaccessible.
- Minimal pinned Goose patch or library integration at command dispatch and tool-response serialization.
- Another pinned Goose release only if current primary evidence proves the missing contracts; a version bump alone is not a fix.

Preserve Rust, Goose, external Bifrost, distinct OS identities, durable claims, budget enforcement and O4's separate-local-operator/no-MFA decision. Do not weaken the scope or activate workers to obtain a green test.

## Proposed reviewers and cost

Three reviewers: Goose/Rust harness engineer (source/runtime contract), application security reviewer (mandatory boundary and exfiltration paths), and contrarian operations reviewer (maintenance and recoverability). Estimated10–13 agent calls including research, positions and one response round; up to further rounds only if warranted and reported. User confirmation is required by the debate skill before dispatch.

## Acceptance

Record primary-source evidence, rejected options, unknowns and a bounded spike. No recommendation is considered verified until its bypass/secret/termination canaries pass. If evidence is insufficient, retain blocked execution and produce the precise missing proof rather than claim consensus solved the boundary.
