# G03 local holdout fixture runner evidence

Date: 2026-10-27. Scope: evaluator-only local fixture adapter; no worker, endpoint, gateway, standing account or service activation.

`holdout_runner` binds a strict immutable JSON manifest digest and exact candidate revision to `PrefilterSession`. It runs three real subprocess attempts per scenario, each with a fresh raw-blob snapshot and Seatbelt scratch directory. Export uses committed blobs, not archive attributes or modified worktree data. Scripts arrive through stdin to the fixed system shell. The existing positive shell/network controls and host read/write denial checks precede execution. Output is bounded in memory; unknown/error/oversized results are never returned as text or counted as a negative vote that other passes could outweigh.

Tests were written first and failed for the absent runner API. The first implementation then failed positive controls because stdin remained open; moving ownership into the bounded writer and explicitly closing it fixed EOF handling. The next run passed all seven initial fixtures. Added limit tests cover zero/excessive time and output limits and oversized manifest scripts.

Real fixtures cover fresh-attempt success, asserted failure, timeout, malformed JSON, unknown result fields, nonzero exit despite passing JSON, stdout/stderr overflow, denied host reads/writes, scrubbed HOME, changed revisions and dirty candidates. Feedback is compared to exact safe JSON; scenario bodies, errors and logs are absent. The success fixture writes an attempt marker only in disposable scratch, demonstrating independent attempts and no candidate worktree mutation.

Final local run: `cargo test -p evaluator` passed 34 tests (9 unit, 9 exact-revision, 8 prefilter, 8 fixture-runner), including the existing real Cargo/Seatbelt fixtures after the shared command-builder refactor.

Evidence boundary: same-UID Seatbelt local tests do not prove distinct-UID holdout secrecy. Manifest authentication, protected store loading, production scenario selection, durable reporting and independent supervision remain missing. Process-group cleanup is not proof against a malicious child escaping that group. The 30-second cumulative budget covers scenario subprocess execution; trusted Git/toolchain/canary preparation is outside it. No claim of end-to-end G03 or production isolation completion is made.
