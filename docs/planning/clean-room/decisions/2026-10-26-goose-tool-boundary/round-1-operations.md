# Round 1 — operations response

Date: 2026-10-27. Responding to [harness](position-harness.md), [security](position-security.md), and the [shared ledger](evidence-ledger.md). No implementation or additional runtime experiment performed.

## Maintain: a bounded falsification experiment, not a stock-Goose commitment

I maintain my position on testing the pinned stock binary first because the extension-loading path offers a concrete hypothesis to test. I agree with both reviewers that the project-hook case belongs at the beginning, before building a full tool service. That ordering addresses my maintenance objection: do not invest in a large wrapper before discovering that startup can bypass it.

The experiment passes this preliminary stage only if a known allowed operation succeeds, the recording provider sees its subsequent request, and planted hooks plus direct forbidden/unknown/recovered tool calls produce no forbidden effect. Test fresh launch, attempted resume and configuration alteration. A hook executing outside the factory boundary falsifies the stock configuration candidate immediately. Neither a clean advertised inventory nor an empty error log rescues it. The relevant source paths are pinned in [harness research, facts 3–5](research-harness.md).

## Concede: minimizing upstream changes is subordinate to owning every reachable path

I concede any implication that avoiding a fork is itself an operational advantage sufficient to choose stock Goose. Security correctly distinguishes registered tools from startup discovery, resource access, notifications and descendant processes. A wrapper with an unowned escape path is harder to operate honestly than a small, explicit patch with reproducible regression tests.

I support source-side normalization before Goose receives factory tool content. However, “sanitize at the producer” must include its error and notification outputs, and must refuse unsupported content. Acceptance requires recording every provider request in the fixture, including requests following errors, retries and partial output. Any synthetic secret reaching that recorder falsifies the tested normalization contract. Passing known sentinel cases establishes only those formats and channels; it does not establish universal prevention of encoded exfiltration. [Security research, facts 3 and 6–7](research-security.md).

## Maintain: cleanup and cost are part of completion

I maintain my position that cancellation is not termination evidence. The [MCP cancellation specification](https://modelcontextprotocol.io/specification/2025-06-18/basic/utilities/cancellation) permits requests that cannot be cancelled to ignore the notification. Acceptance therefore requires independently observed child/process cleanup or quarantine that prevents reassignment. Kill the supervisor while a tool is active, interrupt the response after its side effect, and deliver a late result after the attempted lease transition. No duplicate active work or attachment of that result to another attempt is acceptable.

For the offline fixture, known request identities and synthetic usage must reconcile exactly with the attempt ledger. Missing usage, uncertain billable acceptance, truncated capture or unresolved tool execution must prevent a successful receipt. The test should prove those refusal paths, not merely a happy-path total. External Bifrost reconciliation remains a separate gate; no fake ledger result upgrades that evidence. I agree with harness that a useful candidate diff and an exact-SHA wall pass remain separate from successful generation and accounting. [Harness position](position-harness.md); [operations research, facts 2 and 6](research-operations.md).

## Maintain: unresolved descendant enforcement must stay explicit

I maintain my position on literal R13 coverage. Both reviewers now identify the same gap: accepting a build command does not prove mediation of every child command. A top-level policy marker is insufficient. The experiment must separately record which command decisions were mediated and which descendant effects were prevented by OS policy. If the required descendant guarantee cannot be demonstrated, record R13 as unresolved; do not describe tool exclusivity as completing it.

The parties appear aligned on the experiment, but this is not consensus on a deployable architecture. After a failing stock canary, the next reviewable deliverable should identify the exact failing path, minimal protected-launch or pinned patch, build provenance, rollback artifact and regression cases. A version bump or library rewrite does not pass by default. Evidence remains **ADEQUATE for the bounded spike, INSUFFICIENT for activation**.
