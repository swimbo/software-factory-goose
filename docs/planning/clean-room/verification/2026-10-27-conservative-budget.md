# Conservative per-call budget component — 2026-10-27

Scope: bounded G-04/R7 work in `gateway.rs` and `workflow.rs`. No external gateway/model request, live Restate invocation, provider selection, service startup or worker activation occurred. The existing duplicate-virtual-key rejection was preserved.

## Change

`GatewayClient` starts without reviewed model contracts and denies every model until trusted bootstrap supplies one. A contract binds an exact model identifier to a review digest/validity interval, integer microUSD-per-million effective input/output prices, full hard maxima for billable input/output tokens, a fixed-call surcharge ceiling, a request byte limit and the explicitly reviewed output-limit field. These are trusted configuration assertions, not independently verified provider facts or cryptographic attestations.

The effective input/output prices must cover overlapping surcharges, cache behavior, reasoning and routing markups. All other charges must fit the fixed-call ceiling. Unknown/unbounded charges cannot safely use this contract. No real contract or provider price is selected by this implementation.

Reservation in microUSD is:

`ceil(max_input_tokens × input_rate / 1,000,000) + ceil(max_output_tokens × output_rate / 1,000,000) + fixed_call_ceiling`

Checked integer arithmetic rounds each component upward. It reserves the entire reviewed input AND output maximum, even if the caller requests a smaller output cap. `InferenceBudget` no longer accepts a caller-supplied dollar estimate. Its output token request must be positive and within the reviewed maximum. Forwarded requests explicitly set the reviewed limit field, `n=1` and `stream=false`.

Only bounded text messages with supported roles are accepted; media, tools, extra message fields and unknown models fail before HTTP. Missing/negative/zero price or token values, invalid review metadata, oversized requests, expired/future reviews and numeric overflow fail closed. Review validity is checked again after reservation and before forwarding. Any reservation already made is retained on later failure or ambiguity.

Governance still reports floating dollars; an upward-rounded conversion is used only for local headroom comparison. The authoritative reservation request now sends an exact JSON integer to `BudgetCounter.try_spend_microusd`. That exclusive object handler uses checked `u64` arithmetic and a default 750,000-microUSD unit ceiling.

Both the old floating `try_spend` handler and new integer handler bind/check `ledger_mode` under the same exclusive object key. Cross-mode calls, mixed key families, unknown modes and incomplete recorded mode bindings deny. Preexisting legacy `spent` or `cap` keys prevent integer admission, including zero-spend legacy records. There is no migration/reset route; migration of nonempty legacy counters remains unavailable. Existing legacy callers retain their prior arithmetic but cannot coexist with an integer ledger for the same key.

## Test evidence

1. Initial test-first RED: 15 missing price-contract/helper symbols.
2. Initial local HTTP regression exposed that a one-ULP floating cushion was lost across the JSON roundtrip: the receiver observed `0.0012` where the sender-side calculation expected `0.0012000000000000001`. The assertion was retained until the wire contract changed to integer microUSD; it was not weakened with a tolerance.
3. Integer/mode test-first RED: 24 missing ledger/helper symbols.
4. Final `cargo test --locked -p control-plane --all-features --lib`: **92 passed, 0 failed, 0 ignored**, including 12 gateway tests and the new integer/mode tests.
5. `cargo clippy --locked -p control-plane --all-features --lib -- -D warnings`: **passed**.
6. Scoped `git diff --check` and rustfmt: **passed**.

Local random-loopback HTTP fixtures observed exactly 1,200 microUSD for the synthetic reviewed 1,000-input/100-output limits even when requested output was one token. They checked the forwarded output field and single nonstreaming completion. Failed/unreadable governance, insufficient headroom, false/malformed/unavailable reservations prevented forwarding. Unconfigured/unknown/expired models and unpriced payloads produced zero HTTP calls. Arithmetic tests cover per-component upward rounding, invalid values, overflow, exact ceiling and one-microUSD overage. Mode tests cover legacy zero/nonzero state, cross-mode calls, cap-only legacy state, mixed state and unknown modes.

## Remaining limitations

No evidence yet proves that a real provider honors the selected output field, configured hard billable maxima or reviewed effective prices. Request fields alone do not enforce upstream behavior. Text-only support intentionally cannot yet carry the full Goose tool conversation. All enabled inference paths must still be forced through the authority boundary, with authenticated budget identity, actual usage/retry reconciliation, daily cumulative authority and operator-controlled cap changes. No live Restate concurrency/replay/migration proof was performed. G-04 remains partial; this does not establish full budget enforcement.
