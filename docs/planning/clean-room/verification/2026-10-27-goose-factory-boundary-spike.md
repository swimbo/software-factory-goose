# Actual factory boundary through protected Goose/MCP

Date: 2026-10-27. **Six local Goose-driven cases passed through the real Rust execution boundary.** The factory-owned adapter restricted its tool interface to `shell(command)`, invoked `execution --tool-request`, and returned its validated, masked response to the recording provider. This establishes this specific integrated route; it does not establish mandatory interception of every reachable Goose path or close G02.

## Artifacts and reproduction

- [Experimental MCP adapter](../../../../clean-room/crates/execution/adapters/mcp_stdio.py), with [four unit tests](../../../../clean-room/crates/execution/adapters/test_mcp_stdio.py).
- [End-to-end fixture script](goose_factory_boundary_spike.py).
- [Observed results and exact model-bound tool messages](2026-10-27-goose-factory-boundary-spike.json).
- [Earlier protected-configuration canaries](2026-10-27-goose-protected-config-spike.md) and [raw versus masked model-bound controls](2026-10-27-goose-mask-boundary-spike.md).

From the repository root:

```sh
cargo build --manifest-path clean-room/Cargo.toml -p execution --offline
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover \
  -s clean-room/crates/execution/adapters -p 'test_*.py'
python3 docs/planning/clean-room/verification/goose_factory_boundary_spike.py \
  --goose /absolute/path/to/audited/goose \
  --execution clean-room/target/debug/execution \
  --summary /absolute/path/to/new-evidence.json
```

Recorded hashes:

| Artifact | SHA-256 |
| --- | --- |
| Goose v1.49.0 executable | `6bc711de29cd43bcf1e3ac7a3193b453dd0348068192947079c3cb871542319c` |
| Execution executable built offline | `34221267e2b305cc344a80eff33f146074423d874d50d40b0d4b2937dd100625` |
| MCP adapter | `16792a91b9bece59eb567ff894277ea7e3e01b40c6b98a4d8bc83e83c57824bd` |
| Fixture script | `395724326f6138738fb64abeec82615a0d9c4d20d1a9b71a027d2fb81b3edb4f` |

The Goose digest and version were rechecked; the execution and adapter copies were hashed for this run. The adapter uses Python's standard library only and is an experimental bridge for the fixture, not a selected production transport architecture or installed service. The execution policy/supervision/masking implementation remains Rust.

## Exercised route

The deterministic local provider issued a `factory__shell` call. Goose dispatched to the protected stdio adapter, which accepted only a command argument and invoked the real boundary using trusted executable, policy, and working-directory paths. Model arguments could not select those paths or environment values. The boundary evaluated policy before launching a shell, supervised the child, and assembled/masked complete stdout and stderr before release.

The adapter validated the response shape, dropped raw worker stderr, and represented refusals or nonzero child exits as MCP tool errors. Its schema exposes no file/resource/media tools. Unknown adapter operations receive a fixed protocol error. This does not by itself prove that Goose has no alternate operations.

Each case had a fresh protected launch/configuration root and separate writable task directory. The fixture copied the execution executable and adapter outside the writable roots. Its Seatbelt test profile allowed network access only to the loopback provider port, denied actual user-home reads, and limited writes to task/runtime paths. An external-connect probe returned `EPERM` before every invocation. All provider data and credential placeholders were synthetic; no external model or Bifrost call occurred.

## Results

Every case advertised only `factory__shell`, made two local provider requests, returned a tool message visible in the second request, and completed without timeout. The model's final fixed text was only a liveness control, not a successful-execution receipt.

| Case | Boundary response observed by model | Independent effect |
| --- | --- | --- |
| Allowed fixture | `executed`, exit 0, `VISIBLE_ALLOWED` stdout | Expected marker created |
| Blocked `./dd` fixture | `refused: policy_denied` | Marker absent |
| Split-secret output, exit 7 | `executed`, exit 7, both streams `[REDACTED]` | No synthetic key/password in any provider request |
| Invalid UTF-8 in stderr | `refused: output_withheld` | Neither output stream released |
| Model-supplied `cwd` field | `refused: invalid_request` | Runnable fixture did not execute |
| Write outside task root | `refused: policy_denied` | Outside marker absent |

The allowed and blocked fixtures had identical executable script bodies; only the blocked basename differed. The allowed marker establishes that the script would execute when admitted. The masking case's secret was produced by a local script, not embedded in the model-issued command, so absence from the complete request capture was meaningful. That script emitted a provider-key-shaped string in two writes, a synthetic credential assignment on stderr, and exit code 7. Redaction preserved the failure status.

All four adapter unit tests passed: authority fields rejected before launch; malformed worker responses/raw stderr withheld; refusals and nonzero exits remain MCP errors; boolean exit codes rejected. The fixture source passed syntax inspection, and assertions verified all six recorded cases. Full request captures are hashed in the summary; exact tool messages are included directly.

## Limits

This is a local shell-text route only. Untested here: forged alternate tool names, extension enablement, resume, subagents, other plugin roots, symlink/race attacks, resources/media/structured content, notifications, helper/adapter death, cancellation, watchdog behavior, and real usage reconciliation. Prior notification-to-model coverage remains unexercised. The command policy is still a partial shell filter, and masking does not guarantee protection against arbitrary encoding or cross-stream reconstruction.

The adapter trusts the bounded execution binary and does not replace its process supervisor. Its timeout handling is not proof that every descendant dies after adapter failure. Distinct OS identities, production sandbox/network policy, authenticated transport, and protected configuration provisioning remain separate gates. Runtime authority is supplied by trusted fixture argv; that assumption is not a deployed identity boundary.

Raw runtime files remain at `/private/var/folders/3b/9571c77j0078bs3mpjrqcxj80000gn/T/sfactory-real-boundary-3fjqj6l3` and may expire. The local server was shut down after the run. No factory worker, global Goose configuration, or service was enabled. Continue the outstanding bypass and lifetime canaries before claiming mandatory all-path enforcement.
