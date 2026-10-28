# Gateway client with disposable Restate budget authority

The existing Rust `GatewayClient` now has a disposable integration fixture against the real Restate `BudgetCounter`, with synthetic loopback governance and inference responses. A trusted synthetic model contract sets a worst-case reservation of exactly 250,000 microUSD per call. A new journal key admits three calls and denies the fourth before the provider is contacted. A second key confirms that an inference request returning synthetic HTTP 503 still retains its reservation: two more calls succeed and the next is denied before inference. The first key remains exhausted after both graceful and SIGKILL Restate restart; each post-restart attempt makes zero provider calls.

The fixture uses the existing temporary PostgreSQL/Restate replay harness and only its owned processes and databases. Run from the repository root after building the other replay fixture examples described in [Restate replay](2026-10-27-restate-replay.md):

```sh
cargo build --locked --offline --manifest-path clean-room/Cargo.toml -p control-plane --all-features --example gateway_restate_fixture
PYTHONDONTWRITEBYTECODE=1 python3 clean-room/tests/fixtures/restate_replay.py
cargo clippy --locked --offline --manifest-path clean-room/Cargo.toml -p control-plane --all-features --example gateway_restate_fixture -- -D warnings
```

The rebuilt example and full replay fixture passed, including existing approval, intake, claim and promotion checks. The fixture-specific Clippy check passed.

The fixture also inserts a fixed-route loopback proxy that waits for Restate to acknowledge a successful 250,000-microUSD reservation, then drops that first acknowledgement before the client sees it. The ambiguous call returns an error with **zero provider calls**. An explicit retry makes a second reservation and one provider call; one further call makes the third reservation and another provider call; the next request is denied before inference. The exhausted lost-ack ledger remains exhausted across both graceful and SIGKILL restarts. This demonstrates conservative double reservation on retry, not idempotent reconciliation. There is no production change or automatic retry in this test.

This proves the actual text-only client's request-to-integer-budget-counter integration against a local disposable Restate journal, not Goose tool traffic or production routing. Governance and provider responses and prices are synthetic; no real Bifrost, model, credential, private ingress or separate UID was used. A provider failure retains the full reservation. In-flight SIGKILL, daily authority, actual billing and idempotent replay reconciliation remain unproved. The production `GatewayClient` is unchanged and its tool conversations remain refused.
