# Phase 11A spending and billing continuation — 2026-10-30

**Phase incomplete; candidate disabled; live paired runs 0/120.** This is verified source and disposable local journal evidence, not deployed spending authority, production admission or performance evidence. Concurrent implementation and existing ledgers were preserved.

## Approved policy

The user approved **$5 per day** in this chat on 2026-10-30. `clean-room/crates/execution/harness/benchmark-spending-policy.json` records 5,000,000 microUSD/day and the existing 750,000 microUSD/task ceiling. The journal uses authoritative UTC days. Permanent task totals span attempts and days; a new attempt or midnight never resets task allowance. Opening task/day reservations must be explicitly inventoried. Actual costs never refund conservative reservations. The policy file requires protected supervisor binding before use; its presence does not activate anything.

## Implemented source

- `harness_spending.rs`: one owner-scoped Restate object atomically reserves both task and daily headroom. Immutable bootstrap binds reviewed all-path maximum charges, launch/lease/attempt/route digests, approved policy and predecessor-fence inventory. Call identities and sequences are immutable; dispatch begins once. Unknown effects retain their reservation and block another call in that attempt. Missing day inventory, stale scope, revocation and exhaustion deny admission. No reset, refund, automatic migration or eviction exists.
- Durable generation claims bind receipt IDs globally to one exact call/manifest. Completion requires every reviewed component's authenticated paid receipt evidence or authenticated non-dispatch closure for an unused alternative. Missing logs never establish non-dispatch. Claims and completed receipts survive restart.
- `billing_receipts.py`: bounded authenticated Vercel generation lookup, exact decimal amounts, strict generation/provider/model correlation, complete supervisor-owned physical-call manifests, and mandatory durable receipt-ID claims. It rejects unknown/estimated/BYOK costs, incomplete manifests, reuse and malformed/truncated/oversize responses. Credentials travel only through child stdin; lookups have a five-second process deadline, fixed HTTPS origin, no environment proxies or redirects, and sanitized failures. No inference is dispatched.
- `billing_spending.py`: claims and completes through the **same** authenticated owner journal supplied by the protected supervisor. It binds all component dispositions and consumes every collected physical receipt exactly once. Lost acknowledgements remain unknown. It does not create another spending ledger.

The production entrypoints remain unregistered. Direct JSON handlers, digest fields and injected callbacks are not authentication. A protected runtime adapter must authenticate bootstrap, launch liveness/revocation, route review and collector provenance, fence predecessor spending paths, and keep journal access inaccessible to workers. The disposable loopback fixture intentionally does not establish those deployment properties.

## Verification

- 48 Python harness tests pass, including ten new receipt/settlement tests; six new Rust journal tests pass. Scoped Ruff formatting/lint and strict example Clippy pass.
- The real disposable Restate fixture races ten exact reservations and ten begin requests: one dispatch admission, no duplicate charge. It SIGKILLs only its own server and reopens the same owned journal. Unknown effects, daily denials and generation claims persist. The collector subsequently settles the same journal; tiny actual costs do not restore reserved headroom.
- Review found an initially nondiscriminating opening-inventory oracle. The original fixture incorrectly passed when its opening spend was replaced with zero. The corrected fixture uses 399,998 opening microUSD plus two 300,000 reservations against a 1,000,000 **synthetic fixture** cap: a third reservation must be denied. A real-journal negative control that drops opening spend now fails the oracle, while the unchanged fixture passes. This fixture cap is not benchmark authorization. The two-microUSD remainder also makes the no-refund boundary discriminating: refunding the first reservation down to its two-microUSD actual cost would incorrectly admit the next 300,000 reservation.
- Review also found that re-claiming receipt IDs after restart could hide a lost original claim. The fixture now requires a conflicting manifest to be refused **before** legitimate collection can recreate anything. Its negative control skips the original durable claim; the old oracle passed incorrectly and the corrected oracle rejects that execution.
- Code review completed with nine lenses and independent validation (`phase11a-spending-20261030`); both retained fixture findings were fixed inline. The opening-inventory issue was separately found during simplification. No source findings remain unresolved within this component milestone. The intended publication snapshot also passes its six Rust journal tests.
- Initial new-module tests failed on missing imports/types before implementation; that compilation evidence is not claimed as a demonstrated behavioral mutation test.

Reproduce the source checks:

```sh
cd clean-room
cargo test -p control-plane --features restate --example harness_spending_fixture --offline
cargo clippy -p control-plane --features restate --example harness_spending_fixture --offline -- -D warnings
cargo build -p control-plane --features restate --example harness_spending_fixture --offline
python3 tests/fixtures/harness_spending_replay.py
```

The replay script uses the existing macOS Restate installation in its documented fixed location, fresh private temporary state, loopback ports and synthetic receipts. It neither contacts Bifrost/providers nor touches existing factory journals. Native Linux protected deployment remains unverified.

## Live benchmark admission remains blocked

1. Bind the approved $5 policy, actual reconciled task/day opening reservations, authenticated launch scopes and exclusive predecessor fencing to the protected runtime. Source components and a disposable loopback journal are insufficient.
2. Supply reviewed enforceable charge/token bounds for **every** auto embedding/classifier/fallback/answer/retry path. No rates or hard limits were invented from catalog estimates.
3. Obtain complete, correlated provider-recorded billed receipts for all physical calls. Fresh read-only gateway observations found 11 factory Flash log rows, three missing costs; one classifier log row had no cost. Neither set had parent links. These counts are a diagnostic snapshot, not a complete dispatch manifest or invoice.

[Vercel documents generation-specific balance debits](https://vercel.com/docs/ai-gateway/sdks-and-apis/rest-api), which the new collector supports for non-BYOK generations. [Ollama's current public usage schema](https://raw.githubusercontent.com/ollama/ollama/main/docs/openapi.yaml) provides account/team time buckets and model grouping, without a documented per-request billing filter. Shared-account deltas and frozen-token-price calculations do not establish per-attempt billed costs. A genuine per-attempt billing source for the unchanged answering route has not been demonstrated.

Accordingly no paid benchmark attempt was sent. No key, price, route, service, existing ledger, fence, deployment or candidate activation was changed. The frozen 20-task, three-repeat paired suite and its safety/acceptance/10% cost/10% time thresholds are unchanged. Missing receipts cannot pass; the baseline stays selected.

The current journal bootstrap accepts a fixed catalog of lease-bound attempts. A protected runtime still needs authenticated admission of subsequently issued launch grants (preserving the same task/day totals), general Goose transcript authorization, the independent task acceptance runner and a resumable 120-attempt driver. These are not supplied or proven by this component milestone. They cannot establish the missing external billed-cost source.
