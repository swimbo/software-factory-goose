# Operations research: Goose tool boundary

Reviewer: contrarian operations. Researched 2026-10-27. Scope: pinned Goose 1.49.0, commit `71fc4be1ed729e26b1dc0a4466abdd03be548a53`; no execution or implementation. Evidence supports a bounded experiment, not worker activation. Position paper awaits the shared ledger.

## Evidence summary

1. **Release identity is available, runtime guarantees are separate.** The official [v1.49.0 release](https://github.com/aaif-goose/goose/releases/tag/v1.49.0), published 2026-09-03, identifies commit `71fc4be`. The local [protocol audit](../../verification/2026-10-26-goose-protocol.md) records matching published/archive SHA256, executable SHA256, and scrubbed version/help probes. This reviewer inspected cached pinned source and current primary pages; did not repeat binary execution. Matching a release digest does not establish reproducible source-to-binary provenance.

2. **Completion output conflates termination causes.** Pinned [session source lines 1740–1797](https://github.com/aaif-goose/goose/blob/71fc4be1ed729e26b1dc0a4466abdd03be548a53/crates/goose-cli/src/session/mod.rs#L1740-L1797) breaks after stream error or cancellation and subsequently constructs `completed` metadata. Cost can be absent when totals cannot be retrieved. Operational inference: stdout completion is an observation, not authorization to declare successful execution or zero spend.

3. **Recovery can change the effective tool inventory.** Pinned [builder lines 574–604](https://github.com/aaif-goose/goose/blob/71fc4be1ed729e26b1dc0a4466abdd03be548a53/crates/goose-cli/src/session/builder.rs#L574-L604) handles resume before `no_profile`: resume loads session extension state; only the non-resume no-profile branch starts empty. Non-resume no-profile also skips that branch's plugin MCP collection. This proves useful configuration behavior, not absence of every internal tool surface.

4. **Hooks are unsuitable as the sole operational control.** Pinned [agent construction](https://github.com/aaif-goose/goose/blob/71fc4be1ed729e26b1dc0a4466abdd03be548a53/crates/goose/src/agents/agent.rs#L465-L472) gives subagents an empty hook manager. The [post-tool wrapper](https://github.com/aaif-goose/goose/blob/71fc4be1ed729e26b1dc0a4466abdd03be548a53/crates/goose/src/agents/state_machine/ops_toolcalling.rs#L295-L311) preserves the result and notification stream. A runbook saying “enable hooks” cannot certify universal enforcement or replacement of secret-bearing output.

5. **A protocol cancellation is not a reap acknowledgement.** The primary [MCP cancellation specification, revision 2025-06-18](https://modelcontextprotocol.io/specification/2025-06-18/basic/utilities/cancellation), makes cancellation optional and permits ignoring requests that cannot be cancelled. Inference: the factory needs independently observed process termination before safe reassignment; a cancelled RPC is insufficient.

6. **Turn limits do not establish aggregate cost.** Pinned [environment documentation](https://github.com/aaif-goose/goose/blob/71fc4be1ed729e26b1dc0a4466abdd03be548a53/documentation/docs/guides/environment-variables.md#L14-L20) identifies auxiliary fast-model calls. Its [session settings](https://github.com/aaif-goose/goose/blob/71fc4be1ed729e26b1dc0a4466abdd03be548a53/documentation/docs/guides/environment-variables.md#L130-L148) document child budgets, background tasks, and an optional switch suppressing a naming call. Pinned [context documentation](https://github.com/aaif-goose/goose/blob/71fc4be1ed729e26b1dc0a4466abdd03be548a53/documentation/docs/guides/sessions/smart-context-management.md#L15-L40) includes automatic summarization. These are surfaces to measure; this review does not claim which fire in the restricted configuration.

7. **Patch maintenance crosses active internal boundaries.** The same release notes include new agent-loop/inference crate boundaries and multiple tool-visibility/security changes. Inference: a small patch by line count can still require substantial recurring semantic regression work. No measured engineering-hours estimate is available.

8. **Current recovery remains deliberately incomplete.** Local [execution source](../../../../../clean-room/crates/execution/src/main.rs) and [readiness note](../../../../../clean-room/crates/execution/README.md) block live Goose. Process-group supervision is tested locally, while distinct-UID isolation, an independent supervisor-death watchdog and mandatory interception remain open. This is repository evidence, not deployed assurance.

## Option matrix

| Option | Support and constraint | Operations fit |
|---|---|---|
| Restricted stock Goose plus factory MCP | `no_profile` is useful; resume and internal surfaces need inventory/bypass proof | Preferred experiment: fewer upstream modifications, but factory owns tool service and protocol tests |
| Minimal pinned patch/library integration | Can target dispatch/result/terminal paths; universal coverage unproven | Contingency if configuration cannot close a concrete path; own build, rollback artifact, semantic regression matrix |
| Hooks or status-parser-only wrapper | Demonstrated gaps in subagents, output replacement and completion semantics | Reject as sufficient boundary |
| Unexamined newer release | No reviewed evidence repairs these contracts | No operational justification for a version-only change |

## Proof gaps and smallest spike

Use the pinned binary, fresh protected configuration, no resume, no real credentials and a local recording model endpoint. Record every advertised tool and every model request. Request forbidden commands, extension management and nested work; inject synthetic secrets into tool results, errors and notifications. Kill the tool server and supervisor at request/result boundaries; require bounded cleanup, no escaped work and an explicit unknown outcome when evidence is incomplete. Exercise missing usage, retries and cancellation with fake accounting. Re-run against a deliberately altered inventory to prove the gate fails.

Preliminary recommendation: **ADEQUATE** evidence for this restricted-stock spike; **INSUFFICIENT** for production closure or a confident patch-versus-wrapper selection. Keep execution blocked. Estimate maintenance effort after counting exercised surfaces and observed failure modes, rather than assigning an unsupported cost advantage.
