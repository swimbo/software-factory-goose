# Position: contrarian operations reviewer

Date: 2026-10-27. Based on the [shared evidence ledger](evidence-ledger.md), all three research briefs, and the pinned sources in [operations research](research-operations.md).

## Recommendation and assessment

Approve one bounded restricted-stock Goose experiment, with an explicit stop condition and a narrow-patch contingency. Evidence is **ADEQUATE for the experiment and INSUFFICIENT for activation or final architecture selection**. Do not select a library integration simply because it offers more control, or accept stock configuration simply because it avoids a fork. Select the smallest surface whose failures can be observed, reproduced and recovered without trusting the generator's account of events.

The decision brief is sound because it retains disabled execution and separates artifact verification from promotion. Its largest operational weakness is treating “restricted tools,” “truthful completion,” and “recovery” as independently finishable concerns. They meet at the same failure boundary: a tool may have changed the workspace or incurred model cost before its acknowledgement disappears. An implementation that masks ordinary successful output but cannot reconcile that uncertainty is not ready to run unattended.

## Evidence-backed rationale

The pinned CLI can emit completed metadata after a stream error or cancellation. Optional cost does not establish final accounting. These are verified source properties, not evidence that every invocation fails. Therefore the factory must classify outcomes using independent observations, preserve uncertainty and reject receipts whose evidence is incomplete. A passing artifact evaluation also cannot retroactively prove the generator terminated cleanly or that its costs were fully reconciled. [Pinned response loop](https://github.com/aaif-goose/goose/blob/71fc4be1ed729e26b1dc0a4466abdd03be548a53/crates/goose-cli/src/session/mod.rs#L1740-L1797).

Recovery changes the configuration question. The builder checks session resume before no-profile, while agent construction separately discovers hooks. Thus a clean advertised tool list at initial startup does not prove the same boundary after resume, plugin creation or later configuration changes. The first experiment should prohibit resume and deliberately plant a project plugin, rather than assume a fresh home neutralizes workspace-origin configuration. [Builder](https://github.com/aaif-goose/goose/blob/71fc4be1ed729e26b1dc0a4466abdd03be548a53/crates/goose-cli/src/session/builder.rs#L568-L625); [harness research](research-harness.md), facts 3–4.

The MCP specification permits uncancellable requests to ignore cancellation. I reject any proposed recovery sequence that releases a lease merely because Goose or an MCP client emitted a cancellation event. Reassignment requires observed process termination or an explicit quarantine preventing another attempt from running concurrently. [MCP cancellation, 2025-06-18](https://modelcontextprotocol.io/specification/2025-06-18/basic/utilities/cancellation).

## Strengths

- **The existing stop is valuable.** It prevents a compatibility experiment from silently becoming production execution. Keep the live guard independent of spike configuration.
- **Pinned artifacts make failures repeatable.** Retain archive and executable hashes, source revision, configuration digest, fixture version and observed protocol. The provenance audit already supplies the initial identity record.
- **Independent verification is retained.** Exact candidate/base revisions and wall evidence are a stronger basis for promotion than assistant text. Keep human approval action-bound and separate from generation.
- **Primary-source disagreement is productive.** The newer release's narrower terminal-error fix creates an upstream-derived repair candidate. It does not settle the distinct tool, secret and accounting contracts. [Shared ledger](evidence-ledger.md); [harness research](research-harness.md), fact 8.

## Ranked concerns

1. **False success after an incomplete run is the highest-severity risk.** Do not award a successful execution receipt from exit zero, a terminal JSON label or a useful diff. Require observed child exit, complete bounded capture, no unresolved tool operations, reconciled usage and independently obtained candidate revision. Where those conditions cannot be observed, preserve an unknown or failed outcome; do not fabricate zero cost or success.

2. **Recovery can repeat effects.** A timeout does not identify whether a tool finished before acknowledgement loss. Give each attempt and tool invocation stable identities in the fixture, then inject failure before dispatch, after side effect and before response. Demonstrate that late responses cannot attach to a new lease. This is a proposed acceptance contract, not a claim that Goose already provides transactional tools.

3. **Configuration drift can bypass the broker.** Workspace plugins and resumed extension state are separate inputs. Require a recorded effective inventory and tests that create or alter configuration after startup. If stock Goose executes a planted hook outside the broker, stop that option and specify the minimum protected-launch or code change. Do not keep adding optional hooks to compensate.

4. **Cost limits are broader than turn limits.** Pinned documentation identifies auxiliary calls and separately configured child budgets. Require the recording provider to enumerate every request, including tested retry and auxiliary paths. Admission reservations must survive ambiguous cancellation until reconciled; any conservative over-reservation policy must be explicit. This is an operational requirement inferred from the uncertainty, not a claim that current gateway wiring implements it. [Pinned environment settings](https://github.com/aaif-goose/goose/blob/71fc4be1ed729e26b1dc0a4466abdd03be548a53/documentation/docs/guides/environment-variables.md).

5. **Maintenance cost is currently unknown.** Counting patch lines understates regression work across result, notification, resource, error and process paths. The release changed internal agent-loop boundaries; a library embedding has no verified stable integration contract here. Require a pinned build recipe, rollback artifact and replayable canary suite before selecting a maintained patch. [Release](https://github.com/aaif-goose/goose/releases/tag/v1.49.0); [security research](research-security.md), facts 3, 6–7.

## Missing considerations and concrete changes

The spike needs positive controls: an allowed tool must create its expected marker and the recording provider must receive its next request before absence of forbidden effects counts as evidence. Otherwise a broken fixture can appear secure. Include broker death, supervisor death, pipe retention, missing usage, synthetic secrets split across chunks, and malformed policy. Unsupported content types should produce bounded refusal until explicitly handled.

Clarify R13's descendant-process requirement before claiming closure. Gating a model-requested build command does not automatically mediate every command executed by that build. Security's research identifies this gap. A successful restricted-tool experiment may still leave literal every-descendant enforcement unresolved; preserve that status rather than reinterpret the accepted requirement.

Keep test artifacts as evidence: request sequence, tool inventory, process observations, masked captures, candidate revision and accounting reconciliation. Measure fixture runtime, failed cases and changed upstream surfaces; use those observations to estimate ongoing maintenance. No defensible dollar or engineering-hour estimate exists yet.

## Hard stances

1. No production activation from flags, hooks, hashes or a green negative test without positive controls.
2. No lease reassignment on cancellation alone; no successful receipt when termination, side effects or cost remain uncertain.
3. No silent relaxation of R13/R14 to make either stock Goose or a patch pass. A bounded spike may finish with a precise blocker.
