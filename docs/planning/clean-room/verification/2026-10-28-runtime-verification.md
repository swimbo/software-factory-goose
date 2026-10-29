# Late Phase 9 verification — uncapped NUC run

The user waived all monetary caps for this named INT-LOOP, including the $0.75 task ledger. Existing production defaults are unchanged. Phase 9 remains in progress; no phase or preliminary gap is closed by component tests.

## Current local gates

- Locked/offline, all-target/all-feature Rust workspace: 408 passed, 0 failed, 2 ignored. [Raw output](2026-10-28-uncapped-workspace-tests.log).
- Both runtime-dependent ignored cases were subsequently exercised by the actual disposable native Restate/PostgreSQL replay and diagnostic projection fixtures. The replay includes acknowledged/lost replies, concurrency, graceful and SIGKILL restart, and exact Git CAS promotion. [Replay](2026-10-28-uncapped-full-restate-replay.log), [projection](2026-10-28-uncapped-diagnostic-projection.log).
- Workspace formatting, strict Clippy and doctests passed; all examples built. [Examples](2026-10-28-uncapped-examples-build.log).
- Python fixture discovery after stream, repeated-holdout and aggregate-gate fixes: **111 passed, 0 failed**. [Raw output](2026-10-28-uncapped-python-fixtures.log). This is a current snapshot, not coverage or mutation certification.

## Isolated acceptance contract

The host-held CLI holdouts now run all seven scenarios three times in fresh networkless containers, requiring two passing votes for every scenario and at least 90% of all 21 executions. A subsequent independent story audit caught that the first repetition change enforced only the per-scenario vote, allowing an insufficient 14/21 aggregate; the collector and finalizer now both reject this. The already observed actual candidate had 21/21 and is being revalidated under the corrected gate; candidate-written unittest results are separate and do not substitute for holdouts. Infrastructure errors abort, rather than count as an ordinary failed vote. Finalization rejects missing, malformed or stale repetition evidence and verifies evaluated blob hashes again after Git commit. The manager deadline is bounded at 540 seconds plus cleanup, increased to accommodate the actual 22 sequential challenge executions. The known reference and actual candidate both completed all 22 isolated challenges and independent cleanup on the NUC.

## Stream compatibility

The parser admits only the observed bounded `reasoning_details` text/index/type shape and ignores it as metadata. It retains strict single-tool identity, argument and completion checks. Bounded SSE comments are compatible with the [WHATWG parsing rules](https://html.spec.whatwg.org/multipage/server-sent-events.html#event-stream-interpretation); Bifrost documents its normalized [reasoning details](https://github.com/maximhq/bifrost/blob/dev/docs/providers/reasoning.mdx). These upstream references describe compatibility, not proof of the deployed image's behavior; the retained NUC response supplies that observation.

Provider captures are sensitive host-only task data in private directories. A literal credential-byte refusal is not a general secret scrubber. No captured text is printed or copied into repository evidence. Old ambiguous run fences are retained and never reset or replayed.

## Still open

The live generation/evaluation slice passed; the full intake/qualifier/decomposition/journal/queue INT-LOOP with approved promotion, protected production identities/catalog, exclusive authority migration, host-manager/daemon/host recovery, complete story/artifact audit, enterprise gate and final acceptance remain open. See [preliminary gaps](../plan-gaps.md). Existing Hermes/Stapled services and data are preserved; shared Restate, Docker and Bifrost services are not restarted or migrated.

## Actual candidate evidence

Two live auto-routed turns completed; fixed writer result and durable run fence reached `done`. Candidate `b468844bcfb6a3ec4e337efe8e2e6d45cdedbd90` is based on `40b84df26736e522e0e98180d836b24e021d788b`; evaluated and committed blobs match. Seven scenarios passed 3/3, and candidate tests passed. The strict aggregate-gate revalidation passed another 21/21. [Evaluation](2026-10-28-real-int-loop/evaluation.json), [revalidation](2026-10-28-real-int-loop/revalidation.json), [diff](2026-10-28-real-int-loop/candidate.diff), [scoped provenance](2026-10-28-real-int-loop/scoped-run-evidence.json).

The candidate repository is clean. `refs/heads/accepted` is absent; the proposed exact-ref request is prepared, not approved or executed. No human approval or production deployment is inferred from test results. The independent [boundary audit](2026-10-28-late-phase9-boundary-audit.md) reconciles current operating gaps.
