# Retained provider account construction checkpoint

Date: 2026-11-02. Bifrost source commit `a3d8d3b5b455a1da1de073866672bc0525e77eea`, pushed on `codex/remaining-source-audit-20261031`.

The new Linux `LoadFactoryGatewayAccount` constructs the account needed by the future protected bootstrap from only `ollama-cloud` and `vercel-classifier`. It uses the actual concrete DB provider getter and existing `BaseAccount`, preserving provider/key configuration without importing config files or starting the core, MCP, warmup, workers or HTTP. It requires exact independently reviewed SHA-256 key-ID sets and one typed client-policy row with inference auth on/direct keys off. Unknown, missing, duplicate, disabled, blank or external key channels and raw capture/response, retries and insecure TLS settings are refused. The returned account has a private provider map and no DB backlink; a subsequent DB change does not silently replace the loaded channel.

## Verification and review

- The initial new Go tests failed because the constructor was absent; the installer pin test failed because its new artifacts were absent.
- On the NUC, six focused Go groups, including 22 negative subcases, pass under `-race` against disposable public SQLite data. The full transport library suite passes. No actual provider credential was loaded by these tests.
- A query observer verifies no unrelated provider rows are hydrated; a default HTTP transport observer verifies no HTTP requests. A bulk-getter overlay mutation fails that test while the unmodified constructor passes.
- Review traced an otherwise hidden pre-approval side effect: `SecretVar.Scan` can invoke a globally installed Vault resolver. A counting-hook test reproduced one resolver invocation and an accepted resolved Vault key before the fix; a second regression reproduced acceptance of an environment-backed key. The constructor now refuses an installed resolver **before hydration** and rejects secret references even when their values resolve. Both regressions pass afterward.
- The caller must use the dedicated, serialized bootstrap before workers or concurrent resolver/configuration installation. The function does not disable or rewrite a global resolver. That process-lifecycle obligation remains part of the unfinished production constructor.
- Direct SQLite cases cover zero/multiple client rows, NULL/text policy values, and independent raw-request/raw-response/retry/TLS/disabled/blank settings. Two initial fixture setups did not create their intended DB states: the provider setter defaulted the disabled boolean, and the duplicate-row insert omitted required timestamps. Corrected direct DB controls now exercise the intended states; no shared setter was changed.
- Seven-lens review completed (`20261102-retained-account`) with one independently validated finding, fixed and verified afterward; both testing gaps were addressed. Claude transport was unavailable before egress, so the independent adversarial pass used the local fallback.
- Nine Python installer tests and Ruff pass. The exact source preimage `105202557a5cd19b3dcc61189982c2f7315c130fd43d8ee61d3867f8ad4dcfb5` was reconstructed. Final account sources installed successfully; an altered account artifact and installer replay were refused without source changes. Native account/test hashes and five inspected dependency hashes match the reviewed local files.

[Commands, results and source hashes](2026-11-02-retained-provider-account.json).

## Remaining production work

This is a source construction primitive, not the complete Bifrost bootstrap. The production constructor must supply protected stable state/reference pins, bind the current route/model/endpoint snapshot and actual credential association, construct the real governance/routing/embedding/classifier pipeline, install the concrete final-wire authorizer, qualify plugin/log-sink custody, and give semantic warmup its owned bounded lifecycle. The Root launcher/listener must then be joined to that process with production readiness and failure cleanup.

Provider-supported pre-dispatch all-path bounds, production handed-socket cleanup and remaining NUC loss qualification stay open. No activation or paid inference occurred. Candidate disabled; live benchmark 0/120; $5/UTC-day and $0.75/permanent-task caps remain unchanged.
