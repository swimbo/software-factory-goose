# Protected adapter cancellation and timeout

Date: 2026-10-27. Status: scoped local verification, not G02 closure or runtime activation.

The first new Rust regression test failed on the existing implementation: after SIGTERM to the execution parent, an in-group descendant survived and wrote its delayed marker. The repair adds cooperative TERM/INT handling to the opt-in `--tool-request` process, checks cancellation in its supervisor, and kills the private shell group before returning a fixed refusal. The experimental adapter now observes cancellation concurrently rather than waiting for the shell call to finish.

Independent review identified another concrete defect: `try_wait()` reaped the group leader before a later group signal, and `Drop` could signal the same numeric group again. The supervisor now uses non-reaping `waitid(WNOWAIT)` observation, retains sole child-wait ownership until group cleanup, signals before the single reap, and clears ownership afterwards. Inherited SIGCHLD handlers/automatic child reaping are rejected before spawning. The Python adapter's post-`communicate` group signal was removed entirely. These changes avoid signalling a group number after relinquishing its leader's PID; they are not a claim about arbitrary process-tree isolation.

## Behavior

The fixture-only adapter exposes trusted launcher argument `--timeout-secs`, finite and greater than zero through 190 seconds, default 190. Tool arguments still contain only `command`; the model cannot override authority or timeout. While one request runs, the adapter continues reading bounded frames. Matching cancellation, transport EOF, SIGTERM, or SIGINT signals its active worker through the existing trusted execution process. Timeout and uncertain worker outcomes return `execution_unavailable` without partial output. Cancellation/disconnect suppresses the original response, and a typed unrelated request ID does not cancel active work.

The cancellation shape follows the [MCP 2025-06-18 schema](https://github.com/modelcontextprotocol/modelcontextprotocol/blob/main/schema/2025-06-18/schema.ts): `notifications/cancelled` carries the previously issued `requestId`. Cancellation races can arrive after completion; this fixture tests requests known to be running, not every possible delivery race.

## Reproduction and artifacts

```sh
cargo build --manifest-path clean-room/Cargo.toml -p execution --offline
cargo test --manifest-path clean-room/Cargo.toml -p execution --offline
cargo clippy --manifest-path clean-room/Cargo.toml -p execution --offline --all-targets -- -D warnings
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover \
  -s clean-room/crates/execution/adapters -p 'test_*.py'
python3 docs/planning/clean-room/verification/goose_adapter_lifetime_spike.py \
  --goose /absolute/path/to/audited/goose \
  --execution clean-room/target/debug/execution \
  --summary /absolute/path/to/new-evidence.json
```

- [Reproducible protected lifetime fixture](goose_adapter_lifetime_spike.py).
- [Final lifetime results, provenance, and exact responses](2026-10-27-goose-adapter-lifetime-spike.json).
- [Six-case real Goose policy/masking regression rerun](2026-10-27-goose-factory-boundary-lifetime-regression.json).
- [Adapter source](../../../../clean-room/crates/execution/adapters/mcp_stdio.py), [adapter tests](../../../../clean-room/crates/execution/adapters/test_mcp_stdio.py), and [Rust integration tests](../../../../clean-room/crates/execution/tests/tool_request.rs).

The fixture copies the built execution binary and adapter to protected temporary paths, uses fresh configuration and task directories, verifies pinned Goose v1.49.0's digest/version, and denies external network access before each case. It uses the actual Xcode Python binary resolved by `xcrun --find python3`, avoiding the `/usr/bin/python3` launcher's unrelated cache-write warning under Seatbelt. No external inference, credentials, global configuration, accounts, services, or factory workers are used.

The tool prints synthetic partial output, records its shell and descendant PIDs, then attempts a marker after four seconds. Successful controls must create the marker. Cancellation tests require both recorded processes to stop within 2.5 seconds and verify that the marker stays absent after its scheduled time. `ps` treats zombies as non-running; absence of the delayed effect is independently checked. All observations concern owned fixture children only.

## Results

The Rust suite passed 47 tests: 37 unit, four shim, and six request integration tests. New checks prove TERM/INT withholds output and removes in-group descendants, normal exit remains repeatedly observable without reaping until one cleanup, a second cleanup has no owned PID to signal, and inherited automatic reaping refuses before shell spawn. Seven adapter unit tests passed. Strict execution Clippy passed. The six original real-Goose integration cases passed again against the revised binaries, including split-secret masking and forbidden commands.

All eight final lifetime cases passed. Matching cancellation, EOF, TERM, and INT stopped the recorded processes within 0.017–0.039 seconds of the trigger in this run; the 1.5-second adapter deadline stopped them 1.035 seconds after fixture startup was observed. These are fixture observations, not latency guarantees. Real Goose made exactly two local provider calls and its second request contained only the fixed tool refusal, with no partial output.

| Case | Observed result |
| --- | --- |
| Positive control | Full safe response and delayed marker |
| Unrelated cancellation (`"1"` versus integer `1`) | Same positive result |
| Adapter deadline | Fixed refusal, no partial output, no delayed marker |
| Matching MCP cancellation | No original response; subsequent ping works; descendants stopped |
| Input EOF | Adapter exits cleanly; no response or delayed marker |
| Adapter SIGTERM | Clean exit; no response or delayed marker |
| Adapter SIGINT | Clean exit; no response or delayed marker |
| Real Goose deadline | Actual second model request contains fixed refusal only; descendants stopped |

Intermediate fixture results are preserved: `*-initial.json` rejected unrelated launcher stderr; `*-startup.json` stopped because a 0.4-second deadline did not establish that the tool started; `*-pre-pid-fix.json` passed before the later PID-ownership repair; `*-control-deadline.json` rejected a positive control that exhausted its overly tight five-second launch-plus-tool deadline. The final fixture gives non-timeout controls 15 seconds and timeout cases 1.5 seconds, while requiring observed process startup. None of the rejected runs is counted as a pass.

## Remaining proof limits

Only cooperative timeout, MCP cancellation, EOF, and TERM/INT are exercised. Abrupt SIGKILL of the adapter or execution process, a stopped/hung supervisor, parent death, descendants escaping their process group, failed signal delivery, output backpressure, and all cancellation races are not proven safe. The adapter's last-resort direct child kill is not proof of descendant cleanup. A fixed refusal means the result is unavailable; it does not prove that no side effect ever happened or that every descendant was contained.

The local protected profile is not the production distinct-UID launcher. Alternate tools, plugins, resumed sessions, resources/media, notifications, identity separation, gateway exclusivity, budget reconciliation, and independent watchdog authority remain open. The factory worker stays disabled. These results must not be promoted into a claim that all paths or all shutdown modes are enforced.

Final provenance: Goose `6bc711de29cd43bcf1e3ac7a3193b453dd0348068192947079c3cb871542319c`; execution `3f52370bffaa5ac75a7bc9986bd2203c6b2aa144a9151c12783a3359d6d13774`; adapter `71c1aee6f8da6db720e6877dc0c2a75d43c287f5aab877856c6b512573932a60`; fixture `582ceb090ac6340c1082367fa6cf147e41a5d652d698efee474231431461de18`. Raw owned runtime files remain at `/private/var/folders/3b/9571c77j0078bs3mpjrqcxj80000gn/T/sfactory-lifetime-r0o__12i` and may expire. The local provider was shut down.
