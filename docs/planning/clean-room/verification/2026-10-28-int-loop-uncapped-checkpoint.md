# Uncapped INT-LOOP continuation

Continuation starts from `1ad8838`, in late Phase 9. No planning or implementation restart. User explicitly removed all monetary caps for this named INT-LOOP, including the $0.75 task ledger; key expiry/budget and shared router settings remain untouched. Replay, process/output, credential and approval gates remain required. This run override does not change unrelated production monetary defaults.

## Current component verification

- Locked offline workspace all-target/all-feature tests: **408 passed, 0 failed, 2 ignored**. Raw output: `2026-10-28-uncapped-workspace-tests.log`. Ignored database/runtime tests require their separate disposable service checks; this command does not count them as passed.
- Formatting check, strict all-target/all-feature workspace Clippy and workspace doctests passed. Raw output: `2026-10-28-uncapped-clippy.log`, `2026-10-28-uncapped-doctests.log`.
- Task holdout negative controls reject a constant-output candidate, changed content after evaluation, and the constant-output candidate under `python -O`.

## Owned task and evaluation boundary

Prepared only `/tmp/sfactory-real-int-loop-20261028` on the NUC, with baseline `40b84df26736e522e0e98180d836b24e021d788b`. Task: dependency-free Python greeting CLI plus real unittest tests. Candidate allowlist is `hello.py` and `test_hello.py`; baseline README is immutable and `.git` stays outside worker access.

`nuc_int_loop_task.py` creates the trusted task and holds challenges on the host. Its `check_behavior` requires callbacks that execute each challenge and candidate tests in a separate contained candidate boundary; it never launches generated Python on the host. The helper/holdout source must never be mounted into the generator or candidate runtime. Stop both generator/executor roots, verify same-slice emptiness, import only bounded no-follow regular allowed files, and freeze an immutable snapshot before evaluation. Finalization compares evaluated file digests and rechecks the actual committed Git blobs. A report is not permission to promote: action-bound human approval of the concrete revision remains necessary.

## Shared NUC preservation

Read-only check found Hermes dashboard, Hermes gateway and Docker active; `/` had 30GiB available and `/tmp` 30GiB. Existing Stapled factory, Bifrost, databases and other containers were preserved. No live inference, merge, production activation or full project acceptance is established by this component report. Integrated live-run evidence will be recorded separately.
