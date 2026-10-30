# Phase 11A disabled candidate verification — 2026-10-30

## Result

Local candidate components are implemented and tested. Phase 11A is **incomplete**:
the protected generalized relay/Goose integration and independent 120-run paired
benchmark are absent. Baseline remains active; candidate admission is not granted.

## Verification observed

- Initial contract test failed because the candidate module did not exist.
- New review regressions failed before fixes: workspace hashing followed an
  ancestor symlink; normalization could finish after deadline and release success.
  Descriptor-relative snapshot traversal and deadline rechecks now reject these.
- 28 Python candidate tests passed, including the real compiled QuickJS subprocess
  and the actual Rust normalizer. Covers tool authority denial, serial mutations,
  whole-batch validation, call budget exhaustion, split-secret masking, artifact
  scope/symlinks/limits, no host APIs/imports, heap/output limits, active cancellation,
  exact child reaping, unknown metrics, stall intervention and negative paired gates.
- Execution crate all-features/all-targets: 38 existing worker/policy tests,
  14 normalizer tests reusing existing masker/buffer contracts, four shim tests and
  seven request-boundary tests passed (63 total). Strict execution Clippy passed.
- Seven existing MCP adapter tests passed. Scoped Ruff passed; staged diff check passed.
- Actual native Linux ARM64 host (final source): return42 and missing-process-API success controls,
  std-import refusal, memory-exhaustion refusal and broker IPC round-trip passed inside a disposable local
  container with no network, all capabilities dropped, no-new-privileges, read-only
  root, 128 MiB memory and 16 process cap. Local image only; no host service deployed.
- AMD64 under Rosetta failed closed before eval because close_range returned ENOSYS.
  This is neither native x86_64/NUC proof nor a reason to weaken containment.

Commands and pinned QuickJS source/build procedure are in execution/harness/README.md.
Host tools and downloaded sources are scratch artifacts under /tmp/sfactory-phase11a-*;
they are not installed, registered or included in Git. No credentials were used or
read, and no external inference occurred. The installed laptop Goose reports 1.0.16,
not the reviewed 1.49.0 factory build; it was not substituted for pinned integration.

## Coverage limits and prerequisites

The C host has no script-visible filesystem/network/process API and requires OS
containment. Trusted Python broker callbacks are not themselves a sandbox: only
existing bounded/cancellable transports with independent descendant cleanup may be
admitted. These transports, authenticated atomic authority and exact continuation
matching must be integrated before live use. CandidateSession is an opt-in library
interface, not a production MCP server or deployed interceptor.

The offline gate validates measurements/provenance consistency, but does not
cryptographically authenticate booleans supplied in receipts. Its inputs must be
collected by the trusted independent evaluator/accounting path. Public task specs
are frozen; independent acceptance implementations and actual model-run receipts
remain outstanding. Passing synthetic gate tests does not establish savings, cache
hit rates, universal masking, factory acceptance or production readiness.

## Independent code review and fixes

Actual ce-code-review completed (`status: complete`, `Ready with fixes`) at
`/tmp/compound-engineering-501/ce-code-review/phase11a-20261030/review.json`.
Nine lenses ran with a separate validator. No external peer received source because
its whole-tree scope could not exclude concurrent root-finalization work.

All eight confirmed findings were applied inline and verified:
1. Deeply nested RPC/invalid Unicode yields typed refusal and reaps the host.
2. Failed/invalid final normalization withholds output through a fixed refusal.
3. Deleted or renamed tracked directories hash deletion markers; symlink ancestors remain denied.
4. Per-session nonblocking lock prevents concurrent mutations and returns busy before execution.
5. Artifact quota/storage errors return no output or handle and enter stall accounting.
6. Bounded private JavaScript errors are normalized/fingerprinted; unrelated errors no longer false-stall.
7. Stable prefix contains a sorted capability-name index and concise bridge usage; full schemas remain lazy.
8. Finite below/above-cap allocations distinguish the heap limit from a timeout.

Seven defect regressions failed on the pre-fix source; all now pass. The heap test
also fails against an isolated faithful build with only JS_SetMemoryLimit removed:
the finite 40 MiB allocation incorrectly succeeds. The shipping host retains the
32 MiB cap. The balanced mixed-success evaluation regression confirms failed
attempt spend counts (baseline150 versus candidate590 microusd per accepted task),
so cheaper successful samples cannot hide expensive failures.

No actionable review findings were skipped or left unresolved in this source
milestone. The runtime-admission and live-performance prerequisites above remain
unfinished plan requirements, not waived findings or claimed acceptance.
