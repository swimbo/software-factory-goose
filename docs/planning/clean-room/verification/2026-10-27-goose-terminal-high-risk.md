# Extended Goose terminal-path verification

Historical high-risk extension evidence. The [compaction and factory-entry report](2026-10-27-goose-compaction-factory-entry.md) describes the current candidate.

Date: 2026-10-27. This continues G02 with local provider fixtures only. No external inference, real credential, global Goose install, or live worker activation.

## Reproduced failures

The first local patched binary (`d3650d37409e3e207ef1c69c8eb42ee66ff9584dfb91f404602f37b18f1cbaf4`) correctly rejected generic provider errors and cancellation, but still returned exit zero plus successful completion for all four additional terminal paths below in both JSON and stream JSON. [Confirmed failure evidence](2026-10-27-goose-terminal-high-risk-confirmed.json) includes four passing provider success controls and eight reproduced false successes. `--expect baseline` in that artifact means that false success was expected for comparison, not that this was the original official release binary.

| Path | Exact stimulus and branch evidence | Requests per case |
| --- | --- | --- |
| Credits exhausted | HTTP 402; emitted `creditsExhausted` notification | 1 |
| Recovery compaction failure | HTTP 400 with `context_length_exceeded`; second request is Goose's conversation-summary prompt and also fails; emitted compacting failure text | 2 |
| Max-turn exhaustion | `--max-turns 1`; local provider requests a nonexistent tool, with no extension enabled; emitted maximum-actions message on next turn | 1 |
| Provider refusal | Local Anthropic SSE `stop_reason: refusal`, explanation `OFFLINE_REFUSAL`; emitted provider-refused message | 1 |

Both OpenAI-compatible and Anthropic SSE ordinary-success controls are required in both formats. The [initial run](2026-10-27-goose-terminal-high-risk-initial.json) contained a fixture assertion spelling error (`credits_exhausted` instead of the actual serialized `creditsExhausted`); it is retained and not counted as verified credits evidence. The corrected run confirmed the notification and false success.

## Patch extension

The [high-risk patch revision](../../../../clean-room/patches/goose-1.49.0/0001-headless-terminal-errors-high-risk.patch) extends only the same two upstream files against exact v1.49 source commit `71fc4be1ed729e26b1dc0a4466abdd03be548a53`. Four terminal branches now retain `MessageErrorKind::Other` rather than representing failure as ordinary assistant text or notification alone. Credits retain their original notification and add the typed error. The CLI still derives failure from typed data, never from matching output strings. The interactive headless-helper exception remains, although these agent messages now have an error representation that interactive consumers may render differently.

The [initial patch](../../../../clean-room/patches/goose-1.49.0/0001-headless-terminal-errors-initial.patch) is retained solely to identify the earlier binary and its evidence. Apply only the current patch to pristine pinned source; the two patches are alternatives, not sequential patches.

## Verification result

The expanded offline build exited zero. Its preserved candidate binary SHA-256 is `3297cff13a49781b7f4a4e8a33220b36259089a05e234a6c3e8aaafe352d1f17`. [Expanded provenance](2026-10-27-goose-terminal-expanded-provenance.json) records the fixed temporary candidate path, source, patch digest, build command/log, and all evidence digests. Clean application to pristine source reproduced the prepared source byte-for-byte.

- [High-risk suite: 12/12 pass](2026-10-27-goose-terminal-high-risk-patched.json). All eight failure cases exit 1, emit `error`, and omit successful completion; all four provider success controls exit 0 and complete. Exact request counts and the real compaction-summary request are asserted.
- [Original terminal suite: 6/6 pass](2026-10-27-goose-terminal-expanded-basic.json). Generic provider errors and cancellation still fail correctly, while ordinary success remains valid in both formats.
- [Protected factory adapter: 6/6 pass](2026-10-27-goose-factory-boundary-expanded.json). Real tool calls still obey policy and mask complete output before the next model request, including split synthetic secrets and nonzero shell exits. Refused commands do not create execution markers.

All 24 cases used fresh protected sessions, synthetic local-provider responses, verified v1.49.0/digest, and an external-network `EPERM` guard. The same three nonfatal build warnings remain: denied Xcode cache writes, oversized compact-unwind metadata, and failed optional stripping because the existing toolchain lacks `libLLVM.dylib`. No toolchain repair was attempted. The build uses the same existing explicit Rust 1.98 compiler, copied cache, restricted feature set, and network/write sandbox as the [first patch report](2026-10-27-goose-terminal-patch.md), with `--locked --offline`.

The [protected adapter run against the first patch](2026-10-27-goose-factory-boundary-patched.json) passed all six cases: allowed command, denied command without execution, split-secret masking with nonzero shell exit, invalid UTF-8 withholding, caller authority override refusal, and outside-write refusal. Actual model-bound tool messages were captured; synthetic secrets were absent from all provider requests. Only `factory__shell` was advertised.

## Remaining limits

These fixtures prove only the exact paths above and the original generic provider-error/cancellation controls. Recovery after *successful* compaction followed by another context-limit error, proactive threshold compaction, alternate state-machine execution, all finish-reason variants, all provider adapters, recipe retries, and interactive rendering are not verified. No universal terminal-correctness claim follows. Full upstream Cargo tests still need the uncached `env-lock` dependency and were not rerun/downloaded. Restricted-feature debug binary behavior is not release-feature parity. Mandatory interception of every output path, process-family ownership, distinct-UID isolation, billing reconciliation, and final task success remain separate G02/acceptance gates. The live factory worker remains disabled.

## Reproduction

Use an explicitly verified candidate path/digest; neither fixture installs or enables a worker. Output filenames must be new.

```sh
python3 docs/planning/clean-room/verification/goose_terminal_status_spike.py \
  --goose /absolute/path/to/candidate --sha256 VERIFIED_SHA256 \
  --expect patched --suite high-risk --summary /absolute/path/to/new-high-risk.json
python3 docs/planning/clean-room/verification/goose_terminal_status_spike.py \
  --goose /absolute/path/to/candidate --sha256 VERIFIED_SHA256 \
  --expect patched --summary /absolute/path/to/new-basic.json
python3 docs/planning/clean-room/verification/goose_factory_boundary_spike.py \
  --goose /absolute/path/to/candidate --sha256 VERIFIED_SHA256 \
  --execution /absolute/path/to/execution --summary /absolute/path/to/new-boundary.json
```
