# Phase 11A charge and launch preflight — 2026-10-31

Live attempts remain **0/120**, and the candidate remains disabled. The approved $5 UTC-day and $0.75 permanent-task caps, retained reservations, independent evaluator and registry/launch gates are unchanged. Audited usage-rated cost remains a separately labeled performance metric.

## Reviewed bound composition

`harness_charge_bounds.rs` composes each existing `ReviewedModelContract` maximum with its reviewed maximum physical attempt count. It rejects incomplete or duplicate component inventories, missing/expired maxima, overflow, more than 32 possible physical attempts, and a logical call exceeding the permanent-task cap. It includes fallback alternatives conservatively instead of inferring that an unused alternative costs zero. Its resulting `RouteBound` binds the exact review configuration and is compatible with the existing sole-owner spending journal. A separate affordability check rejects minimum planned reservations exceeding $0.75 across all six task attempts, regardless of the day they run.

These APIs perform arithmetic over trusted, externally reviewed contracts. They do not establish that the supplied component inventory covers the gateway, that provider limits are enforced, or that any launcher is admitted. The spending modules are now available to production library consumers; no production endpoint is newly bound or deployed.

Verification: the initial missing API failed compilation; the additional 33-physical-attempt regression failed before its implementation. Final control-plane library suite: **273 passed, one existing fixture-dependent test ignored**. Strict Clippy with `registry-sidecar` passed. The five new charge tests exercise rounding, physical attempt/fallback sums, expiry, incomplete coverage, overflow and permanent-task affordability.

## Current provider evidence

An unauthenticated GET of the [Vercel model catalog](https://ai-gateway.vercel.sh/v1/models) was recorded in `2026-10-31-provider-price-observation.json`, including the exact response hash and unmodified public entries for the classifier and embedding models. It is background evidence, not a frozen tariff or deployed route attestation. Classifier pricing includes input tiers, cache writes, service tiers, Fast and regional variants. The embedding catalog's zero context/output maxima mean unknown; they are not zero-token charge bounds.

[Ollama pricing](https://ollama.com/pricing) lists peak Flash input at $0.30/M and Pro at $1.32/M. The [Flash](https://ollama.com/library/deepseek-v4.1-flash) and [Pro](https://ollama.com/library/deepseek-v4-pro) pages advertise 1M context. An illustrative reservation of exactly 1,000,000 input tokens costs $0.30 for Flash or $1.32 for Pro **before output or preparation**; six Flash reservations alone total $1.80. This arithmetic is not a verified Cloud billable maximum, and does not prove that a tighter supported bound is impossible.

To fit the permanent-task cap across six attempts, average total retained reservations must be at most $0.125 per attempt before opening spend. More model round trips consume that same allowance. A smaller proved billable-input bound and reasoning-inclusive output bound could make the existing route feasible. Neither a prompt-byte limit nor an undocumented assumption about Cloud `num_ctx` supplies that proof.

[Ollama native chat](https://docs.ollama.com/api/chat) documents `prompt_eval_count`, `prompt_eval_cached_count` and `eval_count`; [System One](https://docs.ollama.com/api/systemone) is a different endpoint. Unknown cache subdivisions must not become zero. [Vercel provider controls](https://vercel.com/docs/ai-gateway/models-and-providers/provider-options) must also be reviewed for hosted routing and retries; Bifrost's retry setting alone does not bound a hosted gateway's physical calls. [OpenAI's chat contract](https://developers.openai.com/api/reference/resources/chat/subresources/completions/methods/create) includes reasoning in `max_completion_tokens`, but that is not proof of identical behavior through the deployed Ollama-compatible route.

## Launch admission

A current source audit still finds three missing production integrations: the sole-owner spending endpoint with root bootstrap and predecessor inventory/fence; a generic protected Root recipe for the frozen suite and both typed/QuickJS profiles; and a Linux Runner adapter that consumes authenticated grants and actual cgroup/deadline/cleanup observations. The existing fixed `nuc-goose-write-files-v1` recipe is preserved. The Linux transport fixture and macOS Runner rehearsal do not substitute for these integrations. The concurrent registry transition is preserved, and its historical status is not presented as a fresh live observation.

Admission stays denied while provider bounds and the production chain remain unproved. No paid inference, route edit, registry mutation, deployment, budget reset, candidate activation or performance pass is claimed. See the paired JSON receipt for the typed unresolved conditions.
