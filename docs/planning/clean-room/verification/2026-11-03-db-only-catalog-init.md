# DB-only production catalog initialization

[Bifrost 6c0738c](https://github.com/swimbo/bifrost-local/commit/6c0738c6392b5c33645fe4f1439493a02ef72576) is pushed and its remote SHA verified. The dedicated gateway now has a Linux catalog-construction primitive, `modelcatalog.InitFactoryGatewayFromExistingDB`, that does not require a qualification build tag or select the historical qualification route. It loads existing pricing, usable model parameters and overrides through the actual datasheet implementation, initializes caches and publishes the capability resolver only after successful loading and a final context check. It starts no synchronization worker and does not mark metadata fresh. Ordinary catalog initialization and qualification constructors remain unchanged.

The caller must supply protected stable state before concurrent catalog/resolver changes and own the existing one-shot `Cleanup` lifecycle. This initializer does not select or attest the retained route, associate credentials, validate actual provider charge bounds or grant permission to dispatch. Missing pricing, no usable parameters, load failures and absent/cancelled inputs refuse initialization without replacing a previously installed resolver.

## Verification

Tests were written first: the original source fails with the expected undefined constructor. Public disposable SQLite rows then prove visible pricing and capabilities, actual effective override cost, unchanged persisted metadata, zero HTTP through cleanup, and cleanup of the installed resolver. A store wrapper exposes only the four needed metadata reads; any credential/configuration read or write through another interface method fails. Failure cases include cancellation after metadata loading and preserve a pre-existing sentinel resolver. An initial test diagnostic used the wrong capability JSON field; correcting the public fixture required no product change and the failed log is preserved.

The exact installer-produced source passes the complete model-catalog race suites: modelcatalog 9.968s, datasheet 1.501s, keyconfig 1.043s and live 1.039s. Removing only the final context check with an isolated Go overlay makes the cancellation regression fail at its runtime assertion. All 1,927 canonical installed files still match their manifest afterward.

Thirteen installer tests, Ruff and Go formatting pass. Exact preimage reconstruction adds only the two catalog files to the prior 1,925-file composed source. Corrupt-artifact and replay attempts are refused without target changes. The installer now resolves the framework module from the same pinned source stage; a missing framework root is rejected before writes.

Simplification made no edits. Six local review lenses found no actionable issues or test gaps. The requested Claude peer failed before content egress; the local adversarial fallback completed instead. This review covers the initializer and installer change, not production readiness.

The companion JSON records hashes, commands, source-stage identities and scoped receipts. Full production configuration/route construction, owned warmup and capture, provider bounds, dependency policy and NUC recovery remain open. No retained-route provider calls, deployment or activation occurred; benchmark 0/120.
