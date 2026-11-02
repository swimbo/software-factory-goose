# Native Root launch-bound peer RPC join

Date: 2026-11-02. Isolated x86-64 NUC fixture; no paid inference or production admission.

The existing native Root preparation/attachment/release fixture now starts the actual Root Unix HTTP server and sends requests from distinct real process identities. It uses the actual `Handler`, `gateway_peer_v1`, protected launch records, child/executable/cgroup inspection and namespace inspection together.

- Broker UID 2005 receives HTTP 200 and the exact verified released-parent identity.
- The same broker requesting a same-binary, same-cgroup descendant receives HTTP 503.
- UID 2006 receives HTTP 503 even with the socket's permitted group 2005. The client successfully connects and reads the HTTP denial, so filesystem denial cannot mask the handler UID assertion.
- Peer verification preserves all launch/grant JSON records.

Two isolated archive controls remove either the handler UID restriction or the `gateway_peer_v1` launch-binding call. Each fails at its intended RPC assertion. The canonical supervisor remains unchanged. The final unmodified fixture passes and its source hashes match the checkout. Ruff passes. Code review completed with no findings (`20261102-3e8ca479d9ea`, lite fixture scope). This fixture-only change uses native replay and mutation controls as its verification; it does not change production harness code.

The first UID control exposed a failure-retirement defect: killing only the parent left its holding descendant alive when the fixture tried to remove the cgroup leaf. The fixture now fences its entire owned attempt cgroup and waits for `populated 0` in `finally` before removal. Both assertion controls then fail cleanly with separate fixture-retirement diagnostics. Independent SSH checks confirmed the exact gateway PIDs, cgroups and containers absent for the final positive and both controls. The initial failed control's exact cgroup and container were also independently absent. Retained source stages are preserved.

[Native results, controls and retirement checks](2026-11-02-root-launch-peer-rpc.json).

## Limits

Root construction/current-authority, scope-preimage and guard seams remain synthetic. The client is raw Unix HTTP, not the production protected-path client; the fixture's tmpfs is not an ext4 pathname-custody proof. This joins the real Root handler authentication and launched-process checks, but does not prove the complete production broker/Bifrost route or lifetime custody. All retirement messages describe disposable fixture resources, not production handed-socket cleanup receipts. Production admission remains denied, candidate disabled and live benchmark 0/120.
