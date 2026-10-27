# Real Unix worker backend against disposable services

Date: 2026-10-27. Local synthetic integration evidence only; no production worker, endpoint, account or standing filesystem path was activated or changed.

The existing native Restate + PostgreSQL disposable fixture now invokes `worker_backend_fixture` through `worker_backend_proxy.py`. The proxy creates a fresh mode0700 directory under the workspace and a mode0600 Unix socket, forwarding exclusively to the fixture's explicitly supplied loopback Restate ingress port. The Rust example constructs the actual `UnixRestateBackend`; its ownership, ancestor permissions, ACL inspection, socket identity and kernel-peer preflight checks execute normally. No backend mock or configuration bypass is used. The upstream TCP service remains reachable by other local processes: this fixture does not establish private production ingress or a distinct worker identity.

The example uses unique synthetic task/queue/request identifiers. Scheduling uses direct fixture-only loopback ingress; all following worker operations use the real Unix backend:

- Status before scheduling returns absent state. The backend sends no JSON body or Content-Type to the actual SDK no-argument handler, exercising the empty-body fix.
- Lookup before pull returns no delivery.
- Pull returns the expected task/spec, attempt1 and fixture-worker lease. Lookup and repeated pull return exactly that original delivery.
- Status while leased matches the authoritative active lease.
- Failed synthetic completion transitions to CoolingDown without an active lease. Exact completion retry returns the same stored result; status matches it.
- A forged completion token is refused.

The backend fixture runs after the existing outbox-count and graceful/SIGKILL restart assertions, preserving their isolated expected counts. The combined Python fixture exited0 with both PASS lines: Unix backend operations and original durable replay/recovery checks. Both Rust examples built using `cargo build -p control-plane --features restate --example worker_backend_fixture --example restate_replay_fixture` before execution of `python3 tests/fixtures/restate_replay.py`.

`cargo clippy -p control-plane --features restate --example worker_backend_fixture -- -D warnings`, Python syntax parsing and `git diff --check` passed. The new Rust example was formatted.

Cleanup uses temporary-directory context managers, a bounded example subprocess, proxy shutdown/join and the existing disposable Restate/SDK/Postgres process cleanup. Relay connections have fixed upstream selection, an eight-active-connection cap, a20-second lifetime and a1MiB traffic cap; it is only a fixture relay, not a production authenticated proxy. No service traffic, lease tokens or response bodies are logged.

Limits: this proves the production backend's HTTP/SDK contract against real same-host services, including absent-body status handling. It does not exercise the outer authenticated worker router with separate OS users, prove generator denial of upstream TCP/admin access, launch/reap generated code, test a model provider, or establish supervisor-independent recovery. Restate remains opt-in and the production service registrations remain gated.
