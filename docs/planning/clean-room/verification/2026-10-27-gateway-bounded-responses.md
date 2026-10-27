# Gateway response bounds

The existing reviewed text-only gateway path accumulates HTTP response bodies in bounded chunks before JSON parsing. Governance and inference bodies are capped at 1 MiB; reservation responses at 64 bytes. Oversized, malformed or unavailable responses fail the call. An oversized inference response occurs after the request and its reservation, so the conservative reservation remains spent. Errors from JSON decoding do not include response content.

`cargo test -p control-plane --all-features --locked --offline gateway::tests` passed 17 tests. Local synthetic HTTP fixtures verify exact-limit success, oversized and invalid JSON refusal, an oversized chunked response without Content-Length, and oversized governance, reservation and inference responses. The first two cannot forward inference; the last has already forwarded once and fails to return the body. No provider or real credentials were used.

This bounds accumulated application bodies, not every underlying HTTP allocation, nor total concurrent resource use. It does not add authenticated ingress, streaming responses, tool conversations, a pricing review, cumulative daily authority, or mandatory worker routing. The text-only gate still rejects tools and unreviewed content before network access; G-04 remains open.

## Governance identity binding

A caller could previously select the governance ID independently of the virtual-key credential. The client now defaults to no bound ID, permits one validated ID to be set by trusted bootstrap, and rejects an absent or mismatched per-call ID before any HTTP. A test-first negative fixture and the existing bound positive fixture passed in an 18-test all-features gateway run. This ensures local configuration consistency; it does not prove that the configured ID actually identifies the credential. Provisioning must verify that pairing, and the per-call Restate URL and budget ID still require trusted authority and ingress binding.

## Reservation authority binding

A caller could also supply a fresh budget ID or a different Restate endpoint returning a successful reservation. Trusted bootstrap now binds one endpoint string and unit ID to the client; no binding, a substituted ID, a different endpoint string, and rebinding all fail before HTTP. The endpoint comparison is exact, not URL-normalized. The constructor rejects URL credentials, queries and fragments and restricts unit IDs to ASCII letters, digits, underscore and hyphen. Local all-features gateway tests passed 19/19, including positive reservations and proxy isolation. This binding does not authenticate client construction, prevent a privileged misconfiguration, verify endpoint identity, or supply the missing daily ledger and production ingress. A trusted dispatcher must create clients with the authoritative unit and endpoint.

## Conservative governance arithmetic

A test reproduced binary rounding overstating decimal headroom: the former parser interpreted a large maximum and usage pair with $0.09 exact headroom as $0.125. An initial `arbitrary_precision` attempt caused an internally tagged Receipt round-trip regression in the combined workspace and was removed. Control-plane now uses `serde_json`'s `raw_value` feature only to retain governance amount tokens, and converts those exact decimal strings using checked integer arithmetic: maximum is floored to microdollars, usage is ceiled, and the integer difference is converted downward to floating dollars. Inputs longer than 128 characters, negative inputs, exponents beyond ±1000, integer overflow, and amounts over 2^53 microdollars fail closed. Values smaller than one microdollar conservatively count as zero maximum or one microdollar usage. These limits can deny valid high-value or unusually precise budgets.

The offline all-features gateway suite passed 20 tests, including decimal/scientific notation, fractional microdollars, subnormal and underflow values, integer precision boundary, and 99 large decimal cases which are refused. This is local arithmetic evidence only: it does not establish live governance freshness, authenticated cumulative daily authority, or provider pricing.

The workspace all-features `receipt_tag_roundtrips` regression failed with the abandoned feature and passed after the RawValue change. The governance parser retains both supported response envelopes and rejects malformed records and duplicate matching identities.
