# Retained-route production bootstrap audit

Date: 2026-11-02. Read-only NUC metadata and source inspection; no inference, service change or credential-value query.

## Current route and complete provider scope

A consistent read-only transaction against `/home/bo/.hermes/bifrost/config.db` confirmed the active factory virtual key and its three enabled `auto` rules. COMPLEX selects `ollama-cloud/deepseek-v4-pro:0813`; MEDIUM/default select `ollama-cloud/deepseek-v4.1-flash:1017`. These rule fallbacks are null.

The retained analyzer also selects `vercel-classifier/openai/text-embedding-3-small` for semantic classification, with an LLM fallback to `vercel-classifier/openai/gpt-6-luna`. Both `count_toward_budgets` values are true. Semantic timeout is 2s and LLM timeout 6s; these are not provider charge ceilings. The classifier alias points to `http://pinproxy:9086` with profile `luna-v1`; Ollama points to `https://ollama.com`. Both stored provider retry settings are zero. Neither setting qualifies retries or charges inside the proxy/upstream.

Thus the constructor must retain **both `ollama-cloud` and `vercel-classifier`** and bind the classifier's real proxy/upstream behavior. Ollama-only provider bounds cannot establish the all-path envelope. The null answer-rule fallbacks do not eliminate the configured semantic-to-LLM fallback.

[Selected metadata and observation time](2026-11-02-retained-route-bootstrap-audit.json). This is discovery evidence, not a complete immutable route attestation: target weights/key associations, physical proxy upstream, corpus identity and credential association remain unqualified.

## Why the historical constructor cannot be substituted

The separate Bifrost source checkpoint is `30a0f170f4fdab8ae516170fea0d3f534f6b3bda`. In that checkout:

- `engine/qualification/server_qualification_bootstrap.go` fixes the account aliases to `vercel-classifier` and `vercel-deepinfra`, and requires DeepInfra Flash normalization targets. It is not the retained Ollama answer route.
- `engine/qualification/lib_qualification.go` exposes a two-alias account and rejects other aliases. Changing only the private listener's address would leave the wrong provider scope.
- `engine/transport/factory_gateway_exchange.go` accepts a `FactoryOwnerAuthorizer` callback but supplies no production constructor/authorizer. Its native fixture's authorizer is synthetic. The concrete final-wire authorizer must bind each request to its exact reviewed component and charge envelope before the physical-send check.
- `engine/transport/routing-embedding/complexity/authorizedwarmup.go` requires an explicit bounded grant and corpus match for authorized warmup. Production startup must not detach paid warmup onto a background grant or silently remove semantic classification.

## Required production construction sequence

1. Load a protected immutable snapshot of the actual factory key scope, ordered rules/targets, both provider configurations, analyzer/corpus and credential references. Revalidate changes before admission. Match the scoped credential to the intended key without publishing either value.
2. Construct an isolated account for the retained provider set, actual governance/routing and owner-aware classifier/embedding executors. Disable automatic MCP injection in that dedicated process; keep Goose responsible for tools. Qualify all plugin and logging sinks against credential custody.
3. Install mandatory owner-context enforcement and the concrete reviewed final-wire authorizer, authenticated broker/capture clients and v2 scope validation before any listener admission or startup work.
4. Give semantic initialization an explicit owned, bounded and captured lifecycle, or adopt a proven compatible existing generation without payment. Preserve the selected analyzer and fallback semantics.
5. Hand the Root-bound socket to the dedicated gateway, qualify the complete authenticated exchange, streams/capture and loss cleanup, then satisfy every provider-bound gate before a paid request.

Current shared client metadata has inference authentication on and direct keys off, but automatic MCP injection is not disabled and content logging is not disabled. There are currently zero configured MCP clients and zero enabled custom-plugin rows. These observations do not prove lifetime custody or authorize modifying shared settings. The dedicated bootstrap must establish its own reviewed configuration.

Candidate remains disabled, benchmark 0/120. Caps remain $5/UTC day and $0.75/permanent task across all six attempts. No production bootstrap, provider-bound or cleanup gate is marked complete by this audit.
