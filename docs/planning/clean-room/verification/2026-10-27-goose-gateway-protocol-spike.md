# Goose tool conversation through a synthetic reservation proxy

The pinned patched Goose v1.49.0 candidate completed six existing restricted factory-MCP cases through a new fixture-only loopback proxy and a separate synthetic OpenAI-style provider. The [v3 result](2026-10-27-goose-gateway-protocol-spike-v3.json) and [reservation counters](2026-10-27-goose-gateway-protocol-spike-v3.json.gateway.json) show 12 accepted provider calls and 12 prior 1,200-microUSD synthetic reservations. Each case's sandbox denied both the external-network canary and a direct connection to the provider port, while allowing the proxy port. Existing policy, masking and tool-result assertions remained green.

The proxy accepts only the fixed fixture model, bounded request body, single factory tool schema, specific streaming settings, and one of two checked message shapes. It checks that a tool result names the tool call in the same submitted conversation. The synthetic upstream response is buffered to 1 MiB, checked against a narrow two-chunk SSE fixture form, then returned. A lock-protected in-memory counter reserves before contacting the provider, denies exhaustion, and retains reservations after malformed or oversize upstream responses. Three local negative-control tests cover malformed JSON, oversized length, unknown field, mismatched tool ID, wrong route, exhaustion, malformed upstream output and oversized upstream output. Their initial oversize-input test encountered a connection reset because the server rejected the declared length before the client finished sending; the test was corrected to send just the oversized declared length, and all three tests passed.

Reproduce from repository root (the candidate is temporary and must first be revalidated by digest):

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s docs/planning/clean-room/verification -p test_goose_gateway_protocol_spike.py -v
PYTHONDONTWRITEBYTECODE=1 python3 docs/planning/clean-room/verification/goose_gateway_protocol_spike.py \
  --goose <candidate-path> --sha256 512bc701fca7312be12ae03215a41a0a60fae0848e2c39f167b7f79e510658fb \
  --execution clean-room/target/debug/execution --factory-restricted --summary <new-result-path>
```

This is a deliberately narrow Python prototype, not the Rust `GatewayClient`, Bifrost, a durable ledger or production ingress. Its in-memory reservation amount and provider are synthetic. Its within-request ID check does not authenticate or durably correlate conversation history across calls; it accepts only the fixture's constrained two-message or four-message shape. It buffers a tiny fixed SSE shape, rather than implementing general provider streaming or validating every usage/billing field. A fixture network policy does not establish deployed containment. Real provider billing and hard token bounds, daily authority, credential lifecycle, replay, authenticated private ingress and mandatory runtime routing remain unproved. No live provider, credential or production worker was used.
