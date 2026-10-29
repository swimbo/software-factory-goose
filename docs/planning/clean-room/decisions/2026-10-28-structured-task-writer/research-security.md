# Application security: bounded task artifact writer

## Current evidence

1. The existing policy rejects characters used in ordinary Python source regardless of quoting; it describes itself as a partial shell filter, not a sandbox. Loosening it changes an established security check without adding containment. [policy.rs](../../../../../clean-room/crates/execution/src/policy.rs)
2. The fixture writer accepts only two exact names, nonempty UTF-8 content up to 32,768 bytes apiece and no NUL; it uses a directory descriptor, exclusive no-follow temporary files and hard links that refuse overwrites. It writes sequentially, so crash or cleanup failure can leave partial files or temporary links; it is not a two-file transaction. [nuc_factory_write_files.py](../../../../../clean-room/tests/fixtures/nuc_factory_write_files.py)
3. `FileRelay` records one exact provider ID and arguments and consumes it before invoking the executor. This is in-memory only; the existing durable fence binds an argument digest and records tool-unknown before effects. Both must be wired together, with no automatic replay after interruption. [nuc_structured_file_relay.py](../../../../../clean-room/tests/fixtures/nuc_structured_file_relay.py), [nuc_run_fence.py](../../../../../clean-room/tests/fixtures/nuc_run_fence.py)
4. Current live code remains shell-specific: the MCP worker advertises/calls `shell`, the stream parser requires `factory__shell`, and the service pins the shell schema and reconstructs that name. The file tool schema and relay are fixtures, not an integrated live path. The JSON Schema `maxLength` counts characters while the writer enforces bytes; the whole transport also has a 65,536-byte bound. [nuc_goose_relay_worker.py](../../../../../clean-room/tests/fixtures/nuc_goose_relay_worker.py), [nuc_bifrost_stream.py](../../../../../clean-room/tests/fixtures/nuc_bifrost_stream.py), [nuc_live_goose_service.py](../../../../../clean-room/tests/fixtures/nuc_live_goose_service.py)
5. The evaluator freezes only after `Batch.stop`, hashes a private snapshot, runs each challenge in a fresh owned container with a read-only snapshot, tears it down, and compares snapshot hashes before publication. Finalization checks committed blob hashes against the evaluated files. This supports a scoped fixture, subject to successful actual owner-loss and evaluator gates; generated tests can self-report success. [nuc_int_loop_evaluator.py](../../../../../clean-room/tests/fixtures/nuc_int_loop_evaluator.py), [nuc_int_loop_task.py](../../../../../clean-room/tests/fixtures/nuc_int_loop_task.py)

Local writer unit tests passed 3/3 and relay tests 2/2 in this review. These are synthetic local tests, not proof of Goose MCP integration or an actual writer execution. The brief reports a real attempt3 provider response and shell-policy refusal; that observation alone does not establish file-tool behavior.

## Options

| Option | Security and operational assessment |
| --- | --- |
| A: fixed structured writer | Recommend for this task. Narrow authority to two fixed filenames and content, no shell, same owned executor, explicit provider-call and durable-fence binding. Requires the integration and recovery controls below. |
| B: encode source in shell-safe strings | Retains broad shell execution and introduces quoting/decoding interpretation and brittle source handling. Does not improve the authority boundary; existing policy may reject required syntax. |
| C: loosen shell filter | Broadens all commands using that policy and risks reintroducing syntax bypasses. Not justified for producing two files. |

## Required spike and controls

Before a fresh live attempt, implement a synthetic end-to-end Goose/MCP test that proves the worker advertises only the intended write tool, the pinned initial schema and prompt agree with it, the parser accepts only the exact function and stable provider ID, and the service binds the exact parsed arguments to one durable pre-effect fence. Tool substitution, changed IDs/content, duplicate JSON keys, extra files, traversal, symlinks, existing target, malformed/empty/oversized Unicode, NUL, aggregate frame overflow and replay must fail before writes. Positive controls should prove both exact bytes and a fixed, non-content response. Explicitly test service restart and owner loss before, during and after each file write: partial, timed-out, ambiguous or cleanup-failed attempts remain quarantined, with no overwrite, resume, or automatic retry; no result is released until whole owned executor/worker teardown and the correct slice is empty. Do not assume rollback makes a crash atomic.

Exercise the actual isolated executor and manager recovery with a synthetic request, then independently evaluate a frozen read-only snapshot and verify committed blobs match. The executor must receive only the writer and task workspace, with network disabled and no credential, socket, Git metadata, evaluator, or holdout mount. Verify resource and frame limits align across MCP, relay and writer. Never run candidate code on the host. Promotion remains a separate human action-bound decision.

## Limits

The fixed two-name writer is a task-specific capability, not generic filesystem confinement or production authority. A successful scoped INT-LOOP would not establish production journal and identity integration, holdout provenance, independent brake/recovery, migration, or production verification gates. Host bo, Docker daemon and the existing Bifrost service are trusted in this scoped experiment; UID 1001 workload remains untrusted.
