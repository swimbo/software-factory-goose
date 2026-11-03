# Retained account and core initialization boundary

[Bifrost b4a9295](https://github.com/swimbo/bifrost-local/commit/b4a92955905105887c32a38f264d57afb7b999f8) is pushed and its remote SHA verified. This characterization joins the actual retained account loader to real Bifrost core initialization with the mandatory owner requirement enabled before either runs. No production behavior changes. It establishes a reusable core-construction step, not a complete production bootstrap.

The test creates a private fake SQLite configuration containing the two retained aliases (`ollama-cloud` and `vercel-classifier`) plus an unrelated provider. It loads only the reviewed retained account, initializes both actual OpenAI-base provider SDKs, verifies that the unrelated SDK is absent, makes model calls through the core and shuts the core down. All keys, model inputs and HTTP responses are public fixtures; the endpoint is loopback. Each mode executes in a separate child because the owner requirement is irreversible within a process.

| Mode | HTTP after initialization | Final provider HTTP | Result |
| --- | ---: | ---: | --- |
| Unguarded test control | 0 | 2 | One successful real core call through each retained alias confirms the fixture is reachable. |
| Owner required before account/core initialization | 0 | 0 | Both SDKs initialize; both unowned calls return the actual nested owner-fence error. |

The full library race suite passes in **110.431s**. The exact installer-produced 1,925-file source passes the focused characterization in **5.164s**. A production `CheckFactoryOwnerContext` mutant that returned nil made the protected child send one HTTP request; the regression rejected it at the intended assertion. No canonical production source was changed by that overlay.

The revised source installer changes only the account test artifact/hash. The composed production source is byte-for-byte unchanged. Corrupt-artifact and replay controls, ten installer tests, Ruff and formatting pass. Existing source/race/native evidence remains applicable to the unchanged production code; this checkpoint does not claim a new full production image qualification.

The initial test used the generic SDK error-message accessor, which hides the underlying transport cause. Its failed diagnostic is preserved; checking the structured nested cause corrected the test without a product change. The positive control prevents a missing provider or broken fixture from masquerading as successful owner enforcement.

Five-lens source review completed without findings or test gaps; simplification made no edits. The Claude peer failed before content egress, and the required in-process adversarial fallback completed. Both the prior published source and new installed test stage retain their exact 1,925-file manifests after all runs.

## Next integration work

The production constructor can use the existing mandatory-owner/account/core ordering under its separately reviewed configuration. It still needs an immutable scoped configuration and route snapshot, reviewed credential/key association, actual catalog/governance/routing setup, controlled semantic warmup or generation adoption, explicit classifier storage controls, authenticated listener/Root binding, and complete failure cleanup. The historical configuration loader bulk-reads providers, and ordinary routing initialization starts background generation maintenance; neither is qualified for reuse unchanged.

This fixture has no model catalog, governance, routing or MCP plugins. It does not establish real-route behavior, valid owned dispatch, credential/log-sink custody, all-path provider bounds or fallback billing disposition. The fasthttp policy decision and NUC lifecycle gates remain open. Benchmark 0/120; no hosted retained-provider calls, deployment or activation occurred.
