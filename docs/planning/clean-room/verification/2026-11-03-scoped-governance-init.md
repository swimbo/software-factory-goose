# Scoped governance initialization

[Bifrost 873f565](https://github.com/swimbo/bifrost-local/commit/873f5658481d7c771ab8b3107a74a8d7cf5d0be6) is pushed and its remote SHA verified. Simplification made no edits. Seven local review lenses found no actionable issues; the configured Claude route failed before content egress, and the local adversarial fallback completed. Review receipt: `20261103-085603-1e121ee1`.

The scoped snapshot loader reads one reviewed, unassigned virtual key and its applicable provider/key metadata and enforcement limits. It projects provider keys without credentials, preserves global and selected-key model constraints, and hydrates only the selected credential after metadata validation. Environment/vault references and active secret resolvers are refused. Actual encrypted credentials are decrypted without eager external resolution. The scoped store constructor calls the existing in-memory hydration path with the real config store attached, avoiding bulk virtual-key and MCP loading.

The actual governance store and authorization evaluator permit the fixture answer model while denying absent classifier permission and unrelated keys. Five budgets and five rate limits cover the virtual key, provider configuration, provider, global model constraint and key model constraint; exhausting each denies admission. This does not add classifier authorization to the production factory key. The caller must retain protected stable state before workers or concurrent configuration/resolver changes. No lifecycle worker is activated by this constructor.

## Verification

The final installed 1,931-file source tree has SHA256 `1eae0adb9f0da9ba820426dea87abcc02efeb961da1c1b9795d1b41b30ea4246`. Installation preserves the exact pre-exchange tree pin, changes only the four scoped governance source/test paths, refuses a corrupt artifact before writes, and refuses replay without changes.

On `hermes-control`, the complete installed configstore and governance race suites passed: 59.415s and 100.618s respectively (command exit 0, wall 141.081s). Tests ran offline with readonly module resolution. An isolated overlay omitting global constraints failed the actual store integration assertion: four budgets instead of five. Production source was unchanged by that mutation.

An earlier full run exposed a new encryption-test cleanup that disabled the package test key, plus a missing public pricing fixture outside the relocated source. The cleanup now restores the existing package test key; the public pricing fixture is staged at the existing test-relative path outside the source manifest. The exact failing encryption pair was observed before correction. All final source bytes still match the manifest. Earlier failed stages and logs remain preserved.

Historical cache aliases were dangling. Exact pinned module versions were restored in a private copied source using the official Go proxy and checksum database, with Git authentication disabled; source bytes were unchanged. Qualification then ran with network module access disabled. No shared cache alias was repaired or deleted.

Final native receipts: `/home/bo/sfactory-scoped-governance-final-VawVVk/full-race-v2-status.json`, `full-race-v2.log`, and `omit-global-constraints-result.json`. Private dependency cache: `/home/bo/sfactory-dependency-restore-1rofjr1v`. These retained operational paths are evidence locations, not deployed services.

Full production bootstrap, routing and owned warmup/capture, supported provider bounds, custody and handed-socket recovery remain unqualified. No retained-provider paid calls, deployment or activation occurred. Candidate disabled; benchmark 0/120.
