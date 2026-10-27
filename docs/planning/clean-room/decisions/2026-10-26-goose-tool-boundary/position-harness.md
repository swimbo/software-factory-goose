# Position — Goose/Rust harness reviewer

Date: 2026-10-27. Basis: [shared evidence ledger](evidence-ledger.md), [harness research](research-harness.md), and the security and operations research briefs. Evidence is **ADEQUATE for a bounded offline restricted-tool experiment, INSUFFICIENT for activation or a final architecture choice**.

## Recommendation and assessment

Run the restricted factory-owned MCP experiment first, using the exact verified v1.49.0 binary, a recording local provider, fresh sessions, and an independently observed side-effect fixture. Treat the stock configuration as a hypothesis to falsify. If the project-plugin or terminal-result tests fail, propose a narrowly scoped pinned patch against those demonstrated gaps. Do not start with a full Rust embedding rewrite, and do not mistake an upgraded executable for a solved enforcement boundary.

The plan is sound as an investigation and flawed if interpreted as a configuration-only implementation recipe. The source gives a credible route to restricting advertised tools, but no-profile does not eliminate hook discovery, and the pinned terminal status is demonstrably ambiguous. The right decision now is a test contract with explicit stop conditions. Worker activation remains a separate decision after all identity, network, accounting, cleanup, and verification gates pass.

## Evidence-backed rationale

The strongest evidence for the restricted option is concrete: [extension collection](https://github.com/aaif-goose/goose/blob/71fc4be1ed729e26b1dc0a4466abdd03be548a53/crates/goose-cli/src/session/builder.rs#L568-L625) starts with no configured extensions for a fresh no-profile run and skips plugin MCP discovery. The [tool operation](https://github.com/aaif-goose/goose/blob/71fc4be1ed729e26b1dc0a4466abdd03be548a53/crates/goose/src/agents/state_machine/ops_toolcalling.rs#L678-L713) also checks advertised names for inference-tagged messages. These are useful enforcement mechanisms worth testing, not just documentation promises.

The strongest counterevidence is equally specific. [Agent construction](https://github.com/aaif-goose/goose/blob/71fc4be1ed729e26b1dc0a4466abdd03be548a53/crates/goose/src/agents/agent.rs#L465-L472) loads hooks independently. [Plugin discovery](https://github.com/aaif-goose/goose/blob/71fc4be1ed729e26b1dc0a4466abdd03be548a53/crates/goose/src/plugins/discovery.rs#L154-L183) defaults unknown plugin names to enabled and consults project/local settings ahead of user settings. Therefore protected user configuration alone cannot be assumed to disable a new project plugin. The experiment must exercise that surface before anyone declares MCP exclusivity.

Current upstream supplies a useful narrow comparison. v1.56.0 [derives terminal errors and returns them](https://github.com/aaif-goose/goose/blob/9949cf926cd42f1d128b9991ed23a496ecace896/crates/goose-cli/src/session/mod.rs#L1558-L1679), unlike pinned v1.49.0. That supports studying an upstream-derived backport if needed. It does not prove complete accounting, tool containment, or correct success after every possible partial outcome. No version change is selected by this position.

## Strengths

- The brief preserves Goose and the locked isolation design. A transport experiment can answer the missing question without quietly replacing the harness.
- It asks for independently observed execution and a recording provider. Those observations can detect a forbidden side effect or leaked synthetic secret even when Goose reports success.
- It separates generation receipts from exact-SHA wall verification and human promotion. A terminal observation must never substitute for independent evaluation.
- It keeps worker execution disabled while evidence is incomplete. This prevents a preliminary adapter from becoming an accidental production path.

## Ranked concerns and alternatives

1. **Independent executable discovery invalidates a tools-only inventory.** A malicious project plugin can exist outside the advertised tool namespace. Test project hooks, settings precedence, recipe paths, and attempted resume. If the current binary cannot prevent discovery under the required working-directory constraints, specify a protected, fail-closed factory-mode patch; do not maintain an expanding denylist of plugin names.

2. **The terminal contract is weaker than its label.** The [pinned JSON path](https://github.com/aaif-goose/goose/blob/71fc4be1ed729e26b1dc0a4466abdd03be548a53/crates/goose-cli/src/session/mod.rs#L1739-L1845) can say completed after errors. A parser accepting that field, assistant text, and cost remains wrong. Test a positive terminal event against injected disconnects, cancellation, tool failures, and partial output. Missing evidence must produce failed or unknown execution, never a completed receipt.

3. **A late mask misses earlier or parallel channels.** The [post-tool wrapper](https://github.com/aaif-goose/goose/blob/71fc4be1ed729e26b1dc0a4466abdd03be548a53/crates/goose/src/agents/state_machine/ops_toolcalling.rs#L237-L310) preserves result and notification streams. Prefer sanitization in the factory-owned producer before content enters Goose. Initially permit only explicitly supported content types; refuse other resource/media/structured paths until each has a tested normalization contract. This is a proposed restricted feature scope, not proof that text-only masking satisfies every future use case.

4. **One allowed shell entry point does not mediate all descendants.** I agree with security's R13 concern: an allowed build tool can invoke other programs. The experiment must distinguish a model-requested command decision from descendant process execution. Preserve the accepted requirement and identify the OS enforcement proof; do not silently redefine “every shell command” to fit the adapter.

5. **Accounting and cleanup can remain incomplete after a clean response.** Operations identifies auxiliary inference and cancellation limitations. Correlate all fixture requests, retries, usage, tool invocations, and process lifetimes to one attempt. The live external-Bifrost reconciliation contract remains a proof gap; a fake ledger only tests the factory's handling of those observations.

## Missing considerations and concrete changes

Add a machine-readable experiment manifest recording binary digest, effective launch arguments, protected configuration digest, enabled extension inventory, fixture versions, expected content types, and canary outcomes. This is a proposed evidence format, not a new runtime architecture.

Require positive controls before negative conclusions: an allowed tool must create its expected marker and produce a recorded provider request. Then forge developer, extension-manager, subagent, unknown, and mangled names; attempt plugin/resume bypasses; kill the tool server; and interrupt the supervisor during output. Inspect side effects independently and all provider requests, including retries. Exercise split secrets and truncation boundaries, error metadata, and notification content. A disabled surface must reject a direct call, not merely disappear from a list.

Document terminal outcomes separately: completed generation with known accounting; explicit execution failure; timeout with confirmed cleanup; and indeterminate termination/accounting. Bind any candidate receipt to invocation identity and independently obtained candidate SHA. Wall verification and operator promotion remain subsequent gates. Assistant-message counts must not be presented as verified model-turn accounting.

If a patch becomes necessary, identify the exact failing canary, smallest code boundary, reproducible build inputs, and semantic regression cases before approving implementation. Compare against the upstream terminal-error change; avoid creating a parallel agent loop merely to obtain a convenient receipt.

## Hard stances

No activation from flags, hooks, or JSON status alone. No secret-bearing tool payload enters Goose before the chosen mandatory normalization boundary. No successful receipt when termination, cost, cleanup, or candidate identity is indeterminate. These conditions are measurable and remain binding even if the restricted experiment is otherwise promising.
