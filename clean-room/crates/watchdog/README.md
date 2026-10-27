# Independent watchdog component

Unactivated R9 component. The library supplies a private, independently authenticated stop-only Unix router and a registry of children it spawns. It has no control-plane, journal or database dependency. Existing PIDs cannot be registered.

Verify only disposable processes:

```sh
cargo test --locked -p watchdog --all-features
```

The `fixture` feature builds `sf-watchdog-fixture`; it has no production serve mode. The black-box test supplies a synthetic key through stdin and creates/cleans its own private socket and child group. Do not treat the fixture's same-UID policy as deployed identity separation.

Production remains blocked on distinct accounts and credential protection, a protected listener, independent supervision, worker integration, escaped-descendant containment and crash recovery. Registry state must never be reconstructed from numeric PIDs after restart. The watchdog must be the sole reaper for its owned children.

See [verification and limitations](../../../docs/planning/clean-room/verification/2026-10-27-independent-watchdog.md).

A target can now contain up to 16 directly owned group roots via `create_family` and `spawn_in_family`. Stop closes admission atomically, signals every group before reaping, and reports each group's result. The multi-group fixture includes a suspended worker stand-in. Actual execution/Goose still need a trusted spawn broker; arbitrary regrouping/setsid descendants remain uncontained. See [family verification](../../../docs/planning/clean-room/verification/2026-10-27-watchdog-family.md).

`broker::SpawnBroker` now supplies a separate unregistered authenticated `/launch` router. Requests select only immutable trusted in-process launch IDs; commands, PIDs, identity and environment are never admitted through HTTP. Successful IDs retain the original member receipt, failures stay tombstoned, and stop closes admission. The fixture verifies real Unix transport, three broker-spawned groups and stopping a suspended worker. Production is still blocked: distinct-UID spawn and signal authority need a reviewed OS launcher, and actual execution needs a safe stdio/lifecycle protocol that transfers sole spawn/reap ownership. See [broker proof and remaining gates](../../../docs/planning/clean-room/verification/2026-10-27-watchdog-spawn-broker.md).

The `fixture` feature additionally offers bounded complete stdout/stderr capture and a private `/result` route. Pipe readers never wait on children; the registry retains sole ownership. Production admission rejects captured IO specs. The actual Goose lifecycle harness requires observed MCP/Goose PGID equality before tool launch and has a negative control for the pinned separate-group behavior. It substitutes a fixed synthetic catalogue for execution policy and is not a production adapter. See [lifecycle evidence](../../../docs/planning/clean-room/verification/2026-10-27-goose-broker-lifecycle.md) and [OS authority review](../../../docs/planning/clean-room/verification/2026-10-27-watchdog-os-authority-review.md).
