# NUC protected supervisor deployment

User authorizes scoped NUC host administration through existing Docker permission, continuing a33c9db to production integration/verification, preserving services/data. Prior three-person OS-supervision debate is resumed with actual Linux evidence and now-approved administration. No shared restart/reboot, key/router edits or promotion approval is implied. This experiment remains uncapped.

## Decision

Select the smallest deployable root-owned boundary outside Docker that enforces immutable task launch identity, independent authenticated stop, late-launch closure and restart refusal. Compare systemd transient services/slices plus narrow root helper versus a custom root process supervisor versus retaining Docker-only fixtures. Keep Docker network-none/nonroot workers and the pinned actual Goose/relay contract where justified; do not restart shared Docker.

Concrete candidate: a root-owned, narrowly authenticated Unix service with separate local service/operator/evaluator/worker accounts; root-owned task catalog, per-task persistent slice, fsynced admission closure and one-use launch records. Requests select only opaque IDs and fixed operations, never arbitrary command/PID/path/mount. Worker Docker containers have no daemon socket or host/control network. Root-owned stop path closes admission, freezes the exact task subtree, recursively kills and observes it, retaining closure and freeze when create/start acknowledgement is ambiguous. A pending Docker RPC cannot be treated as cancelled merely because its client died. Establish whether inherited cgroup freezing actually prevents late-start execution before adopting this claim. Root supervisor is not placed inside the workload cgroup or Docker.

Installation inventories precise new accounts/files/units; refuses collisions/partial state, pins source/binaries, writes only factory-prefixed root locations, and has a conservative rollback. Existing bo, Docker/Bifrost/Hermes/Stapled, old slices/unknown fences and retained original Created container remain intact. Operator account is separate, no MFA claim; no new human login key is silently authorized. Stop must remain usable without Docker/database/gateway.

## Research and proof questions

1. Which systemd/cgroup/root-helper boundary can independently constrain late accepted starts and escaped descendants, including supervisor crash? Verify on Linux6.12.107/systemd257/Docker29.8.0.
2. What precise role/account/socket/catalog trust and anti-replay checks are required? How to provision separate operator access without issuing an unapproved human SSH key?
3. Which operations can be tested with new task-owned units/containers and simulated Docker unavailability without restarting shared services? Which recovery claims remain unproven without a maintenance window?
4. What is the minimal implementation sequence to connect this boundary to existing durable intake/queue/Goose/wall/promotion adapters rather than create another unregistered fixture?

Three reviewers: Linux containment/security; Rust/systemd operations; contrarian recovery/usability. Research primary sources and deployed facts; distinguish verified facts from proposed properties. Insufficient evidence means implement discriminating owned canaries, not declare production ready.
