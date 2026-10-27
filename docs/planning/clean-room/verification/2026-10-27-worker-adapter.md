# Private worker adapter component — 2026-10-27

Scope: bounded G-01 integration. Added feature-gated `worker_adapter.rs` and a read-only `WorkerQueueJournal.lookup_pull` handler. No adapter or queue was registered in main, no accounts/groups were provisioned, and no standing service or credential was changed.

## Implemented boundary

`worker_router` exposes only `POST /pull` and `POST /complete`. Tokio obtains the UID from each accepted Unix stream; missing or mismatched connection metadata fails before JSON extraction or backend calls. Neither body fields nor headers select identity, queue, or worker. Configuration requires distinct non-root service/operator/evaluator/worker UIDs, unique worker and queue mappings, and at most 64 bindings. The public router constructor also compares the service UID with the process's actual kernel identity; no same-UID mode or environment bypass exists.

The caller must supply a correctly provisioned private Unix listener and serve it with `WorkerPeer` connection metadata. This module does not provision that listener, verify all OS account/group memberships, or establish isolation from inherited descriptors. Configuration is not proof of provisioning.

Pull forwards the original idempotency ID to the configured queue. Before delivering an assignment it reads `ClaimLeaseJournal.status` and requires exact task/spec/worker/attempt/token/lease matching, active leased state, and a current local timestamp inside the original lease deadline. A repeated pull never renews the deadline; stale, completed, changed or expired assignments are denied. Empty/unavailable queue outcomes do not dispatch work.

Completion uses the new read-only pull lookup, never `pull`: an unknown result ID cannot acquire work. It derives the task from the retained delivery, checks the exact proof, and reads authoritative claim state. Exact already-recorded results may replay after their original deadline; changed or superseded results deny. The queue then forwards completion to the claim journal, whose exclusive mutation performs the final expiry/proof/receipt check. The adapter also validates the returned completion binding.

A status read can race and local clock agreement is not established. The adapter check is defense in depth, not atomic process-start authorization. Authoritative completion checks remain mandatory, and real process launch/reap integration is still absent.

## Private backend

`UnixRestateBackend` uses Restate-compatible HTTP calls over a service-private Unix socket only: no TCP fallback, environment proxy, redirect or generic caller-selected route. Calls and connection preflights have bounded timeouts; request/reply bodies are bounded at the HTTP adapter/reply boundary. The backend checks actual ingress peer UID during preflight, service-owned socket mode 0600, parent mode 0700, trusted non-writable ancestors, stable socket identity and supported ACLs before/after calls. ACL inspection is currently macOS-only; the only tolerated extended ACE is the exact non-granting macOS `everyone deny delete` entry. Other ACLs fail closed.

Reqwest does not expose the peer credentials of its own connection here. Its connection relies on the checked filesystem boundary; preflight credentials are not misrepresented as per-connection reqwest authentication. A service-private Restate ingress/proxy is not provisioned, and these checks do not prove the proxy's upstream Restate listener is inaccessible to workers. That is an activation blocker.

Unknown transport outcomes remain unknown. The adapter neither invents a fresh request ID nor interprets timeout as nonexecution; the caller must retry the same ID and parameters.

## Verification

RED: focused test compilation failed with 19 missing-symbol/type errors before implementation (`/tmp/sfactory-worker-adapter-red.log`).

GREEN:

- `cargo test --locked --manifest-path clean-room/Cargo.toml -p control-plane --all-features --lib`: **109 passed, 0 failed, 0 ignored** (`/tmp/sfactory-worker-adapter-green.log`).
- Eight adapter tests include actual Unix connections and kernel peer credentials, wrong UID/header spoof denial, unknown body authority rejection, missing connection metadata, body bounds, absent scheduling route, immutable pull retry, stale/expired lease denial, unknown completion without claiming, exact result retry, changed result/proof rejection, and caller retry after a synthetic ambiguous acknowledgement.
- A separate service-private Unix mock ingress checks all four exact Restate routes and JSON payloads, including JSON-string pull lookup and an empty body/no Content-Type for no-argument status. Wrong backend UID and changed socket permissions fail before forwarding.
- `cargo clippy --locked --manifest-path clean-room/Cargo.toml -p control-plane --all-features --lib -- -D warnings`: passed. Initial unused test-only import was corrected.
- Scoped rustfmt and `git diff --check`: passed.

Fixtures use unique private directories and Unix sockets, then abort their in-process servers and remove only those fixture paths. No system users, service configuration, databases or volumes were touched. Positive worker transport fixtures intentionally use a private test helper with same-process credentials; the public constructor rejects that synthetic service-role setup. These tests do not prove separately provisioned accounts or process isolation.

The queue/claim decisions in these HTTP tests use a typed mock backend. The private ingress fixture proves HTTP serialization and filesystem/peer checks, not real Restate execution. Live registration, durable concurrent/crash replay, actual upstream privacy, authenticated scheduler integration, clock assumptions, worker process lifecycle and reap remain open. G-01 remains partial and activation remains disabled.

## Live contract correction

The root agent's disposable Restate 1.8.0 integration found that the generated no-argument status handler rejects JSON `null` with Content-Type. The mock was tightened first and failed with HTTP 400 (`/tmp/sfactory-status-contract-red.log`), then the backend was changed to omit both body and Content-Type. This corrects the earlier mock's permissive assumption; the adapter's private-proxy topology still has not been tested against a real Restate deployment.
