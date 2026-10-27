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

Tests use local `/bin/sh` fixtures only, covering malformed receipts, missing cost, large
simultaneous output, timeouts, descendant-held pipes, environment exclusion, policy failures,
and masking before shell output is returned. They prove these local boundaries only.
