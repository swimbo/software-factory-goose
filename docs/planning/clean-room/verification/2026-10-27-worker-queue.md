# Bounded worker queue component — 2026-10-27

Scope: partial G-01/R3/R4 integration. New `worker_queue.rs` exports `WorkerQueueJournal` behind the `restate` feature. It remains unregistered. No HTTP adapter, service, worker, credential, environment bypass or standing infrastructure was changed.

## Implemented contract

The exclusive queue object binds its key to one configured worker. `schedule(ScheduleRequest)` retains an immutable work-package ID plus `LeaseSpec` and initializes the existing `ClaimLeaseJournal` through an awaited SDK object-client RPC. Identical scheduling is idempotent; changing the repository or base revision conflicts. Typed input validation and capacity checks precede child calls. Queue state is saved after initialization; the journaled child call supplies the intended crash/replay boundary, which still requires runtime verification.

`pull(PullRequest)` requires a canonical ULID request ID and bounded TTL. Repeated IDs must carry identical parameters and return the original stored outcome. This includes empty polls: a caller must use a new ID to observe subsequently scheduled work. Successful outcomes contain the original task/spec/lease receipt. They never renew a lease or constitute fresh process-start authority.

The queue calls the authoritative claim object with `expected_previous_attempt: Some(0)`. The claim handler compares this optional precondition while holding its exclusive object context, before expiry or claim mutation. This closes the separate-status-read/claim race and prevents this queue from reassigning an expired attempt. Existing clients omitting the field retain their previous behavior; this backward compatibility is not a security control, and private ingress must restrict access to the appropriate handler surface.

Claim conflicts/expired outcomes become retained `Unavailable` deliveries, allowing the next task to proceed without retrying the refused task. Other child faults propagate. Queue and child worker configuration must match; malformed or foreign child assignments fail closed before queue mutation.

`complete(QueueCompletion)` derives the task from the stored pull ID and requires the exact stored attempt/token. It forwards the completion through the SDK to `ClaimLeaseJournal`, which alone enforces current lease expiry, worker identity, receipt idempotency and stale-receipt fencing. The queue cannot overwrite claim state.

Retention is deliberately bounded at 256 immutable schedules and 1,024 immutable pull receipts per queue. Existing retries still succeed at capacity; new work/polls fail closed. No eviction, reset, automatic requeue, renewal or lifecycle rollover exists. Retaining issued and unavailable entries avoids silently making old work eligible again. Reassignment requires a separate process-reap and retry protocol.

## Verification

Test-first RED: `cargo test --locked --manifest-path clean-room/Cargo.toml -p control-plane --all-features --lib worker_queue` failed with 29 missing-symbol/field errors before implementation (captured in `/tmp/sfactory-queue-red.log`).

GREEN:

- `cargo test --locked --manifest-path clean-room/Cargo.toml -p control-plane --all-features --lib`: **101 passed, 0 failed, 0 ignored**.
- Eight new queue tests cover schedule immutability and serialization, changed worker binding, lost-ack-style stored receipt retrieval without a new claim, stable empty polls, changed pull parameters, exact completion proof binding, unavailable-task retention, inconsistent child assignments, input/capacity rejection and retention without eviction.
- One new claim regression proves a stale first-attempt condition cannot mutate even an expired lease; legacy JSON without the optional condition still decodes. Existing authoritative expiry/receipt tests remain green.
- `cargo clippy --locked --manifest-path clean-room/Cargo.toml -p control-plane --all-features --lib -- -D warnings`: passed.
- Scoped rustfmt and `git diff --check`: passed.

The SDK wrappers and generated internal RPC clients compile against installed Restate SDK 0.12.1. Tests exercise pure queue decisions and serialization, not a live Restate server or an actual lost acknowledgement. No runtime concurrency/crash recovery claim is made.

## Remaining gates

Worker configuration is not caller authentication. Before registration, a private adapter must authenticate each caller, enforce scheduler versus worker permissions, bind each worker to its queue, and prevent direct unauthorized claim calls. It must enforce raw body bounds and check the current authoritative lease before starting any process; replayed queue receipts may already be expired or completed.

Grounded qualification, spec-derived DAG scheduling, intake-to-queue cascade, real worker subscription/process lifecycle, prior-process reap, queue enumeration/retirement, schema upgrades, queue-specific projection/rebuild and runtime fault injection remain open. Existing claim mutations still use their journal-coupled Postgres projection delivery; queue state itself has no added SQL authority. G-01 remains partial and dispatch remains disabled.
