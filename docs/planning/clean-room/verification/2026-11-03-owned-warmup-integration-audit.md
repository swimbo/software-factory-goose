# Owned warmup integration audit

The installed candidate's complete routing race suites pass: routing 1.268s, complexity 2.705s, rules 1.176s. These are existing tests with synthetic embeddings/grants, not a production owner/wallet/capture join. The first relative-directory command reported an outside-module setup failure; the corrected module-import command passed without source changes. The companion JSON records the exact clean environment, command and inspected file hashes, all matching the account/core installed-source manifest.

## Existing integration seam

`RoutingPlugin.WarmComplexityAuthorized` delegates to `SemanticClassifier.WarmAuthorized`. The latter requires a grant with virtual-key identity/access, a live deadline at most 180 seconds away, and the exact ordered corpus digest. It waits boundedly for ordinary warmup, then derives its work context from the supplied context. Cancellation or configuration changes prevent adopting the generation. Existing regressions cover ordinary ungranted startup refusal, wrong-corpus refusal, successful authorized warmup and cancellation before adoption.

`InitFromStore` constructs the classifier with the plugin lifetime context and starts generation maintenance. Wiring the embedding executor can start ordinary background warmup immediately. The dedicated bootstrap must enable mandatory physical-owner enforcement before construction and wire the governed executor before any explicitly owned warmup. Do not give the plugin lifetime context a reusable paid grant merely to make background startup succeed.

Call `WarmComplexityAuthorized` with the existing acquired owner context, carrying its governed identity, bounded lifetime and immutable corpus binding. Do not reuse `warmConfiguredSemanticCorpus`: that historical helper constructs a new grant/root through `PreRequestHook`. The historical qualification campaign itself explicitly uses its existing root for warmup; it still selects a different route and is not a production constructor.

## Capacity and fallback

Read-only metadata confirms 50 stored phrases in each tier, 150 total, under the unchanged retained configuration hash. This count is not a normalized corpus attestation. The candidate batches at most 32 inputs; a successful cold 150-exemplar warmup has batches 32,32,32,32,22, or five physical calls, without an extra scalar dimension probe. Existing bounded-batch tests exercise the same algorithm with 70 public exemplars.

The generic classifier can fall back after `ErrBatchEmbeddingsUnsupported`; its regression demonstrates one rejected batch plus 40 scalar calls for a public 40-exemplar corpus. At 150 exemplars that generic path could require 151 calls, exceeding the shared charge manifest's 32-call ceiling. It cannot be reserved or admitted under that manifest. In the intended governed server executor, malformed batch count/index/dimension is rejected before returning vectors to the routing adapter; no working production fallback or free rejection is inferred. Unknown physical outcomes must remain sticky refusals.

The actual bootstrap still needs to join this explicit API to the authenticated one-use owner root, physical-call inventory and durable capture; reserve startup work under the existing caps; attest the normalized corpus and supported provider input bounds; await readiness; and close/join initialization workers on failure. Ordinary routing generation maintenance also needs scoped-store custody and shutdown qualification. No provider support or billing guarantee was established here. Candidate disabled, benchmark 0/120.
