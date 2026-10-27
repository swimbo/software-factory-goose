# Goose compaction errors and restricted factory entry

Date: 2026-10-27. Local pinned-source patch, deterministic loopback providers, synthetic data only. No global installation or worker activation.

This records the five-file candidate before the [restricted MCP process-group follow-up](2026-10-27-goose-mcp-group-inheritance.md). Its patch is retained as `0001-headless-terminal-errors-factory-entry.patch`; results below remain tied to their original binary digests.

## Compaction and alternate-path repairs

The preceding binary still reported successful completion after a second context-limit error following successful compaction and after proactive compaction failure. The alternate state machine also treated max-turn exhaustion, recovery/proactive compaction failure, and explicit `/compact` failure as successful termination. The fixtures first reproduced these defects, then retained their original results:

- [Legacy compaction failures](2026-10-27-goose-compaction-initial.json).
- [Alternate state-machine initial run](2026-10-27-goose-state-machine-initial.json).
- [Alternate compaction initial run](2026-10-27-goose-state-machine-compaction-initial.json) and [confirmed run including manual compaction](2026-10-27-goose-state-machine-compaction-confirmed.json).

The initial alternate-path assertions expected seven requests for exhausted recovery; the actual bounded path uses five (three failed inference requests and two successful summaries). Its refusal error also uses a different diagnostic string. These were fixture assumptions, not product regressions; the corrected run checks the observed typed failure and exact count. The alternate credits/refusal/repeated-context paths already rejected correctly before this iteration.

The patch retains typed terminal errors in the legacy proactive and repeated-context branches, and in `state_machine/ops_compaction.rs` and `ops_maxturns.rs`. It preserves the repeated-context notification. A successful summary followed by a successful inference remains a passing control; the helper does not reject merely because an earlier context error was recoverable.

The core candidate SHA-256 is `5caec431e32889c87b9f6a58f79a886a3f901e0765dee744f2deb90ab41caa97`. All 54 terminal cases passed on this binary: legacy/basic 6, legacy/high-risk 12, legacy/compaction 8, alternate/basic 6, alternate/high-risk 12, alternate/compaction 10. Both output formats are tested. Exact artifacts and digests are in the [provenance record](2026-10-27-goose-compaction-factory-provenance.json).

## Factory entry restriction

The [execution-path probe](2026-10-27-goose-execution-path.json) established that `GOOSE_STATE_MACHINE=0` alone does **not** force legacy execution. A leading `!` prompt still produces a `bang_shell_` request without any provider call. This matches `agent.rs::reply_impl`, which selects the state machine when either its flag is enabled **or** bang-shell input is detected.

Positive and negative skill controls were exercised: the alternate path advertises `load_skill` and returns a harmless local skill-body marker to the provider; the legacy path rejects the same attempted tool call as unadvertised. The legacy path also rejects `summon__delegate`. No subagent execution positive control was run, so the negative result is not proof that every subagent route is disabled.

The current patch adds an explicit `goose run --factory-restricted` option. Its checks run before input parsing/session construction. It requires fresh noninteractive `--no-profile --no-session`, explicit `GOOSE_STATE_MACHINE=0`, and nonempty direct `--text`. It rejects leading bang/slash commands, resume/identified/scheduled runs, containers, builtin/HTTP extensions, recipes, instruction files, recipe parameters and subrecipes. The factory owns any permitted stdio extension command; this option does not authenticate that command or itself restrict which stdio tools it exposes.

This is an opt-in factory contract. The eventual trusted launcher must require the verified binary, flag and immutable settings. Omitting the flag leaves ordinary Goose behavior available; the disabled production worker has not been wired to this contract. Existing protected launch directories/configuration, shell policy, output masking, and process supervision are still required. `--no-profile` alone does not disable project hooks, as earlier canaries demonstrated.

## Final candidate verification

The final candidate SHA-256 is `3add8f27a0a2b38c5b9ff10fb3a85e95affe842590c70413c5e7901cc3b1b8b1`.

| Evidence | Result |
| --- | --- |
| [Factory entry controls](2026-10-27-goose-factory-restriction-patched.json) | 14 cases passed: valid launch, two unadvertised-tool refusals, and 11 invalid configurations rejected before a provider call |
| [Restricted basic terminal suite](2026-10-27-goose-restricted-basic.json) | 6/6 passed |
| [Restricted high-risk terminal suite](2026-10-27-goose-restricted-high-risk.json) | 12/12 passed |
| [Restricted compaction suite](2026-10-27-goose-restricted-compaction.json) | 8/8 passed, including successful recovery |
| [Protected factory MCP adapter](2026-10-27-goose-factory-boundary-restricted.json) | 6/6 passed with the new flag; policy refusals prevent execution and split synthetic secrets are masked before model-bound tool messages |
| [Unrestricted path controls](2026-10-27-goose-execution-path-unrestricted-regression.json) | All six original behavior controls retained, including the alternate skill and bang-shell positive controls |
| [Interactive before](2026-10-27-goose-interactive-before-guard.json) / [after](2026-10-27-goose-interactive-after-guard.json) | Ordinary `run --interactive` processes its initial prompt, emits completion, then exits cleanly on EOF in both binaries |

The [pre-implementation factory fixture](2026-10-27-goose-factory-restriction-before.json) fails its valid-launch control because the old binary does not recognize the option; retained as the initial red result. The interactive smoke covers initial-response and EOF behavior, not the full terminal UI. Interactive CLI logic is not changed when the factory option is absent.

All runtime fixtures use fresh protected directories, a scrubbed environment, verified executable digest/version and a successful external-network `EPERM` probe. The patch now touches five files. All original files matched the previously verified commit-addressed archive; `git apply --check` passed and applying the patch reproduced prepared source exactly. The existing absolute Rust 1.98 toolchain built offline under the same network/write sandbox. The two incremental builds exited zero (16.92 and 10.08 seconds), with the previously disclosed Xcode-cache, compact-unwind and optional-strip warnings. No toolchain download or global changes occurred this iteration.

## Remaining limits and source findings

Source inspection found additional ordinary-text error responses in alternate recipe-command handling and a stop-hook block-cap warning. Retry error/exhaustion paths already construct typed errors. Those recipe/hook paths were not runtime-tested or patched here. Restricted factory entry prohibits recipe/slash input and builtins, but trusted launch/configuration still must exclude hooks and alternative extension loading.

Universal subagent disablement, alternate transport entrypoints, interactive rendering variants, all provider finish reasons, malformed output after terminal events, and every error path are unproven. Full upstream Cargo unit tests remain unavailable due to the previously recorded uncached `env-lock` dependency; no download was attempted. Restricted-feature debug builds do not establish release-feature parity. Mandatory launcher enforcement, complete interception, distinct identities, watchdog ownership, billing, artifact evaluation and promotion remain separate gates. Live factory execution remains disabled.

Watchdog integration source finding: pinned `extension_manager.rs::child_process_client` calls `spawn_long_lived_mcp_subprocess`; on macOS, `subprocess.rs` calls `configure_subprocess`, whose common Unix setup explicitly uses `command.process_group(0)`. Therefore an MCP adapter is configured to enter a separate process group; inherited Goose group membership must not be assumed. This patch does not alter that behavior. The watchdog bridge needs runtime group/lifetime evidence and a reviewed ownership solution before it can claim adapter cleanup.

## Reproduction

`goose_terminal_status_spike.py` accepts `--suite basic|high-risk|compaction`, optional `--state-machine` for alternate-path testing, and `--factory-restricted` for the permitted legacy factory path. Combining the latter two intentionally conflicts with the factory contract. `goose_execution_path_spike.py --factory-restricted` runs the entry negatives; without it the six original controls run, while `--interactive-smoke` runs the initial-prompt/EOF check. `goose_factory_boundary_spike.py --factory-restricted` exercises the real adapter. Each requires an explicit candidate path/digest and a new summary filename; adapter testing also requires the verified execution binary. The [provenance record](2026-10-27-goose-compaction-factory-provenance.json) lists preserved candidate paths and all evidence digests.
