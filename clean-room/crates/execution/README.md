# Execution readiness

Live `run_goose` is deliberately blocked. No environment flag can enable an unsandboxed
run. The planned distinct worker UID, empty home, Seatbelt deny-read profile, forbidden
control/evaluator/Postgres network access, and mandatory tool interception have not been
provisioned or proven. No accounts, services, or sandbox profiles were changed.

`GOOSE_BIN` is honored in command construction; child configuration clears ambient variables
and admits only the fixed `/usr/bin:/bin` PATH. This is defense in depth, not identity isolation.
The installed CLI's `goose run --help` on 2026-10-26 has neither `--no-session` nor
`--output-format`; it cannot satisfy the planned protocol. No inference was attempted.

The strict parser is based on [current upstream JSON output](https://github.com/aaif-goose/goose/blob/main/crates/goose-cli/src/session/mod.rs)
inspected on 2026-10-26: `messages`, `metadata.status` (`completed`/`error`), and optional
`metadata.cost_usd`. Our parser fails closed when cost is missing/null/negative, or when the
JSON/status/messages are malformed. Assistant message count is a receipt metric, **not**
an authoritative billable-call count. The upstream schema must be pinned and checked against
the selected installed version before enabling live execution; the parser fixture is not a
live compatibility test. Accounting remains dependent on the planned gateway's actual usage.

Subprocess supervision interleaves nonblocking reads from stdout/stderr, retains at most
1 MiB per stream, drains excess bytes, and kills the private process group on timeout and
normal direct-child exit. Cleanup is bounded if escaped descendants retain a pipe; incomplete
or truncated output cannot yield Completed. An OS sandbox must prevent session/group escape.
The pending production launcher also needs an independent watchdog for supervisor death.

The optional `shims/sh` supports only `sh -c <command>` and invokes `execution --run-shell`.
That route checks policy, captures both streams, masks them, and only then returns output.
Truncated or timed-out output is withheld. Bad explicit policy files fail closed. Secret
masking recognizes patterns and common credential assignments; it is not comprehensive DLP.

R13/R14 are **partial**, not complete: PATH interception is bypassed by absolute shell paths,
interpreters, built-in tool implementations, and other MCP tools. The policy parser rejects
unsupported expansion syntax, wrappers, nested shells, parent traversal, known blocked
commands, and detected writes outside allowed roots, but is not a full shell AST or a file
access sandbox. Symlink races and arbitrary code execution need the planned OS boundary.
Final Goose output masking alone would be too late to protect the model context. Mandatory
pre-model tool interception remains a live-readiness blocker.

`tool_output::TextBuffer` is a source-side assembly primitive for a future verified tool
adapter. It retains raw UTF-8 byte chunks privately until the trusted producer reports a
complete logical response, then validates UTF-8 and invokes the existing masker once.
Limits must be between 1 byte and 1 MiB; both retained input and released masked text are
capped. Oversize or unsupported content permanently poisons the buffer. Incomplete,
cancelled, truncated, or invalid UTF-8 responses release no text; errors contain fixed
messages only. No partial flush or raw/debug accessor exists. This is not secure erasure,
and the cap does not claim to bound allocator/regex scratch space.

One buffer must cover the complete logical text payload: masking separate chunks can leak
split secrets, as the offline recording-provider canary demonstrated. Structured content,
resources, media, and unnormalized errors/notifications must be rejected by the adapter.
The primitive has no authority to prove completion or input type; those decisions must
come from the trusted transport, never model arguments. It is intentionally **not wired**
to Goose, the shim, or a mandatory all-tool boundary. Its tests do not close R14.

Tests use local `/bin/sh` fixtures only, covering malformed receipts, missing cost, large
simultaneous output, timeouts, descendant-held pipes, environment exclusion, policy failures,
and masking before shell output is returned. Pure buffer tests cover every split position
of a synthetic key, split UTF-8, hard caps, redaction expansion, poisoning, and incomplete
or unsupported input. They prove these local boundaries only.

## Opt-in factory shell request boundary

`execution --tool-request` accepts one EOF-framed JSON request on stdin:
`{"command":"..."}`. The envelope is limited to 64 KiB, command text to 16 KiB,
and input framing to five seconds. Unknown fields, duplicate fields, malformed JSON,
invalid UTF-8, empty commands, and NUL bytes are refused. Close stdin after the request.
No caller field can select policy, environment, working directory, timeout, or output cap.

The trusted launcher supplies the current working directory and optional `SFACTORY_POLICY`
file; bad explicit policy fails closed. The internal `ShellBoundary` accepts a trusted
canonical directory, rules, timeout (at most 180 seconds), and output cap (at most 1 MiB
per stream). `policy::evaluate_at` resolves relative paths against that same directory,
without changing process-wide cwd. Policy denial happens before spawning `/bin/sh`.
The child has an empty environment except the fixed PATH and uses the existing process
supervisor. Both streams must close completely and pass strict UTF-8, caps, and complete
buffer masking before either is released. Timeout or failure withholds both streams.

The response is either `{"status":"executed","exit_code":N,"stdout":"...","stderr":"..."}`
or `{"status":"refused","reason":"fixed_reason"}`. Exit zero from this transport means
it delivered a JSON response; callers must inspect `status` and the child `exit_code`.
`executed` is **not** a work-package completion, cost reconciliation, artifact verification,
or promotion receipt. Refusals do not echo input or subprocess errors.

This local entry point is connected only to the experimental offline Goose fixture, not
the live factory worker. It is not an OS sandbox, authentication boundary, or universal interceptor. The existing shim
remains a separate route. A verified upstream adapter and distinct identities must make
the request boundary mandatory before live execution can be enabled. The partial policy
still cannot mediate arbitrary descendant code or remove symlink races. Masking covers
each complete stdout/stderr stream separately, not arbitrary cross-stream reconstruction,
encoded secrets, resources, or media. G02/R13/R14 remain incomplete.

Fixture tests prove a runnable blocked command never executes, split stdout secrets are
redacted, stderr credentials are redacted, nonzero exit status survives, invalid UTF-8 in
either stream withholds both, request overrides fail, explicit cwd is honored, stalled
input expires, and timeout/oversize output cannot be released. No external inference is used.

`adapters/mcp_stdio.py` is an experimental stdlib-only bridge used by the protected offline
Goose fixture. It exposes only `shell(command)`, forwards to this boundary using trusted
executable/workdir/policy arguments, validates the response, withholds raw worker stderr,
and marks refusals/nonzero exits as MCP tool errors. It is not installed or selected as the
production adapter, and it does not supply identity isolation or universal interception.
The six-case real-Goose integration evidence is in
`docs/planning/clean-room/verification/2026-10-27-goose-factory-boundary-spike.md`.

The experimental adapter accepts a trusted launcher `--timeout-secs` in `(0, 190]`
(default 190), observes MCP cancellation while a tool runs, and stops active work on
transport EOF or SIGTERM/SIGINT. It suppresses cancelled/disconnected results and
withholds all output for timeout or unknown outcomes. The execution `--tool-request`
route handles TERM/INT cooperatively and kills its shell group before returning a
refusal. This does not prove SIGKILL, adapter death, escaped groups, or hung-supervisor
cleanup; those remain deployment blockers.

The Rust supervisor uses `waitid(WNOWAIT)` to observe exit without reaping, signals the
owned process group before the single reap, and discards ownership afterwards. It
requires default SIGCHLD disposition and rejects automatic child reaping before spawn.
There is no process-group signal after leader reaping. The experimental Python adapter
relies on this cooperative worker cleanup; it never signals a group after `communicate`.
See `docs/planning/clean-room/verification/2026-10-27-goose-adapter-lifetime-spike.md`
for the protected cancellation/timeout evidence and its exact limits.
