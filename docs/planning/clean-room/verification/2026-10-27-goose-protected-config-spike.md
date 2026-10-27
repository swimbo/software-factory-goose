# Protected launch/configuration canary

Date: 2026-10-27. **The bounded protected-launch candidate passed the known project-hook and protected-write canaries.** Stock Goose v1.49.0 ran from an immutable clean launch directory while a fixture MCP tool wrote only into a separate task directory. The known malicious task plugin did not execute in that arrangement; it still executed in the unprotected task-directory control. This keeps a configuration-based candidate viable. It does not establish the complete factory boundary or justify worker activation.

## Artifacts and reproduction

- [Reproduction script](goose_protected_config_spike.py); imports [existing local harness](goose_hook_spike.py).
- [Initial direct-child write results](2026-10-27-goose-protected-config-spike.json).
- [Real model-invoked MCP results](2026-10-27-goose-protected-mcp-spike.json).
- [Original bypass and provenance](2026-10-27-goose-hook-spike.md).

```sh
python3 docs/planning/clean-room/verification/goose_protected_config_spike.py \
  --mcp --goose /absolute/path/to/audited/goose \
  --summary /absolute/path/to/new-evidence.json
```

The binary must match SHA-256 `6bc711de29cd43bcf1e3ac7a3193b453dd0348068192947079c3cb871542319c` and report `1.49.0`. The script checks both. It refuses to overwrite evidence. Current script SHA-256: `3677521fc0916891729254717d4e62ef86ff034b3a77b673529524b362d7800e`; imported harness SHA-256: `b3fbe0c3bb169320a31a754c1b84ed921d228d25223be6e46fb63453c441d95c`. After execution, only the script docstring was clarified to distinguish direct-child and MCP observations; executable behavior is unchanged.

## Arrangement and controls

All paths were new temporary directories. The task directory contained the previously demonstrated harmless `SessionStart` marker plugin. Goose's current working directory was either that task directory for the positive control or a separate clean launch directory for the candidate. The Goose configuration root, clean home, launcher directory, and fixture tool source were outside the permitted write set. Goose data/state and task/tmp writes remained allowed.

The fixture Seatbelt profile denied external networking, allowed only the local stub's TCP port, denied reads under the actual user home, and denied writes except task/runtime-data/state/tmp paths and `/dev/null`. An external-address connection probe returned `EPERM` before Goose ran. Environment variables came from a fixed allowlist; the API-key placeholder and returned usage were synthetic. No user credentials or global Goose configuration were used.

In `--mcp` mode the deterministic loopback provider requested the single advertised tool, `fixture__write_probe`. The minimal stdio MCP server then attempted five fixed writes and returned their outcomes. The provider recorded that tool result before producing `OFFLINE_STUB_OK`. The tool accepts no arbitrary paths or model-supplied write content: this is a deliberately bounded authority probe, not a production filesystem tool.

Fresh CLI runs used `--no-profile --no-session --max-turns 3 --output-format json` and the explicit fixture extension. The same temporary configuration/runtime root was reused across these fresh sessions; no resume option was used. Before each invocation, the parent removed prior fixture markers so absence could not be explained by stale observations.

## Observed results

| MCP case | Local provider requests | Hook marker | Allowed task write | Four protected writes | Tool result reached provider |
| --- | --- | --- | --- | --- | --- |
| Unprotected task cwd control | 2 | `HOOK_EXECUTED` | succeeded | all `EPERM` | yes |
| Protected launch cwd | 2 | absent | succeeded | all `EPERM` | yes |
| Protected launch repeat | 2 | absent | succeeded | all `EPERM` | yes |

All three exited zero without timeout or stderr output. The only advertised tool was `fixture__write_probe`. Protected targets were a new launch-directory plugin, local launch settings, a user-home plugin, and the existing Goose config file. The config digest remained unchanged. The initial direct-child experiment separately observed the same write denials and allowed task write, with one provider request per case and no advertised tools.

In the JSON results, top-level `write_probes` and `write_probes_are_model_tools: false` refer to the direct-child probes. Per-case `tool_observations`, `tool_result_reached_provider`, and final `model_invoked_writes_passed: true` contain the additional real Goose/MCP evidence. The legacy `scope` string describes the narrow discovery/write experiment, not a claim that MCP was absent.

The local HTTP server was shut down and closed after each experiment. Temporary raw captures and generated fixtures remain at the `root` paths recorded in each JSON result; they may expire. Both scripts pass Python syntax inspection, and evidence assertions confirm the table above. The factory execution guard and production source were not changed.

## Decision and limits

No Goose patch is justified by this result: the known discovery failure can be excluded in this bounded arrangement without modifying the binary. This is **not** a claim that configuration alone establishes every required boundary. The accepted candidate still needs a real factory tool interface that preserves task-relative semantics while Goose launches elsewhere, plus immutable launcher/provider/tool configuration across all reachable paths.

Untested areas include alternate installed/plugin roots, ancestor discovery, symlink/rename attacks, environment mutation, resume, extension-management or forged calls, subagents, all output/masking channels, terminal-error truthfulness, accounting, supervisor death, distinct OS identities, and production Seatbelt enforcement. The narrow fixture profile is not the production isolation design. R13 descendant-command coverage remains unresolved. Synthetic usage cannot reconcile real gateway spend, and successful marker probes do not validate candidate code.

Keep live execution blocked. Continue falsification of the restricted candidate; propose a pinned patch only when a remaining concrete path fails and a narrower configuration cannot close it.
