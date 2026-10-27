# Security position: prove the reachable surface before choosing the boundary

Reviewer: application security. Date: 2026-10-27. Basis: [shared ledger](evidence-ledger.md), all three research briefs and their primary sources. Evidence grade: **ADEQUATE for a bounded offline restricted-tool spike; INSUFFICIENT for activation or final architecture selection**.

## Recommendation and assessment

Start with a restricted stock-Goose experiment that attempts to falsify the boundary, using the pinned binary, a factory-owned MCP transport and a recording local provider. Test project-hook execution, resume restoration, extension enablement and forged tool calls before investing in a complete tool service. If any unavoidable path can execute outside the factory boundary, stop that candidate and specify the smallest pinned code change. Do not decide that a patch is necessary merely because configuration has not yet been tested; equally, do not call configuration sufficient because the advertised tools look correct.

The plan is sound as a research gate and unsafe as an activation plan. Its strongest feature is preservation of independent identity, network, budget, verification and promotion controls. Its main danger is collapsing several different guarantees into “mandatory interception.” A tool allowlist controls which registered tool can run; a command policy examines supported shell syntax; OS isolation constrains effects; masking filters selected content. Each requires separate evidence. None substitutes for the others.

## Evidence-backed rationale

The [pinned pre/post-tool implementation](https://github.com/aaif-goose/goose/blob/71fc4be1ed729e26b1dc0a4466abdd03be548a53/crates/goose/src/agents/state_machine/ops_toolcalling.rs) permits calls when hooks are absent, leaves processed results unchanged after post hooks, and preserves separate notification streams. The [agent constructor](https://github.com/aaif-goose/goose/blob/71fc4be1ed729e26b1dc0a4466abdd03be548a53/crates/goose/src/agents/agent.rs#L465-L472) supplies subagents with an empty hook manager. These are decisive grounds to reject hooks as the enforcement boundary.

A restricted configuration has more substance: the [extension dispatcher](https://github.com/aaif-goose/goose/blob/71fc4be1ed729e26b1dc0a4466abdd03be548a53/crates/goose/src/agents/extension_manager.rs) checks tool availability before calling the resolved client. But the harness brief establishes two independent concerns: [resume takes precedence over no-profile](https://github.com/aaif-goose/goose/blob/71fc4be1ed729e26b1dc0a4466abdd03be548a53/crates/goose-cli/src/session/builder.rs#L568-L625), while [project plugin discovery](https://github.com/aaif-goose/goose/blob/71fc4be1ed729e26b1dc0a4466abdd03be548a53/crates/goose/src/plugins/discovery.rs#L154-L183) can supply hooks separately. A process-wide prohibition must therefore cover startup and recovery, not merely model-generated calls.

The [MCP result specification](https://modelcontextprotocol.io/specification/2025-06-18/server/tools) includes structured data, media and resources as well as text. Errors and notifications add further channels in the pinned source. The security objective must identify every model-visible path and either normalize it before exposure or refuse it. “We masked stdout” is not R14 compliance.

## Strengths worth preserving

- **Exact artifact identity:** the provenance report records the source commit and archive/executable digests. This makes regressions reproducible without claiming source-to-binary attestation.
- **Independent verification:** exact-SHA wall checks and human promotion prevent a successful-looking transcript from directly authorizing a merge.
- **Owned, finite tool surface:** a factory transport can present narrow operations whose arguments, outputs and failures are enumerable. This is a testable design direction, not a verified implementation.
- **Offline falsification:** deterministic provider responses and synthetic sentinels let the test demand malicious calls directly, without relying on an external model to discover a bypass.

## Ranked concerns and alternatives

**Critical — startup and recovery can bypass the tool list.** Project hooks can execute before an ordinary tool call; saved sessions can restore extensions. Require fresh sessions and a protected launcher/configuration. Test a malicious fixture plugin in the task directory, ancestor directories and configured plugin paths. A protected launch directory with an explicit task directory is a candidate mitigation, not established behavior. If the binary still discovers executable project content, use a narrow disabling patch instead of a fragile denylist of plugin names.

**Critical — descendant execution exceeds syntax mediation.** R13 says every shell command; the local policy module admits a partial parser. An allowed compiler/build command can execute repository-controlled logic, so a top-level tool check is not proof every descendant command was inspected. Preserve OS containment independently. Explicitly record which calls receive command-policy evaluation and which descendant effects are constrained by OS policy. If the accepted requirement literally demands mediation of every descendant invocation, neither proposed wrapper nor dispatch patch has yet met it; retain the blocker rather than quietly narrowing R13.

**High — masking may occur after another sink.** Pinned post-tool handling invokes large-response processing and telemetry before the hook. Resources and notifications have separate paths. Prefer sanitizing at the factory tool source before Goose receives content, with bounded errors and no raw notifications. Refuse unsupported media/resources unless a tested normalization path exists. The finite regex masker cannot prevent arbitrary encoding of readable secrets; preventing real secret access remains essential.

**High — terminal evidence can overstate success.** The pinned CLI can emit completed after failure. A newer source fix is useful evidence for a targeted change, not proof of cost completeness or process cleanup. Candidate receipts need independently observed terminal cause, complete accounting, claim identity and candidate revision. Cancellation must remain unsuccessful or unknown until subprocess termination is observed. Never convert missing usage to zero.

**High — configuration integrity can erode during a run.** Testing startup configuration is insufficient if a tool can rewrite it or change future tool availability. Protect executable/config paths from the generator, reject altered inventories, and test direct forbidden names after attempted reconfiguration. Retain trusted OS identity separation; the broker must not become an unrestricted deputy for the generator.

## Missing considerations and concrete changes

Publish a small surface manifest covering startup, main tools, nested work, resources, notifications, errors, provider requests, recovery and termination. For each surface record allowed behavior, enforcement owner, failure behavior and an independent observation. Require positive controls: an allowed tool must write a harmless marker and cause a recorded provider request before absence of forbidden effects counts as evidence.

The canary matrix must include missing/malformed policy, broker failure, unadvertised and recovered tool names, extension changes, project hooks, resume, nested/subagent requests, partial output, split-token chunks, truncation and cancellation. Observe all provider requests and forbidden filesystem/process/network effects. Separately test secret-bearing errors and audit metadata; record redaction categories without copying the sentinel. A finite matrix establishes its stated scope, not universal exfiltration resistance.

Keep external Bifrost and production credentials outside this first experiment. Later accounting/network proof must cover every enabled inference path, including auxiliary requests identified by operations. A successful offline recorder is prerequisite evidence, not a replacement for that gate.

## Hard stances

1. No activation while any reachable execution or model-output path lacks an explicit owner and fail-closed test.
2. No hooks-only, PATH-only, completed-status-only or version-only claim of compliance.
3. No weakening of R13/R14 by relabeling untested descendant execution, content channels or unreadable accounting as success.
