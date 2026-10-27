# T6 prerequisite: pinned Goose protocol and interception audit

Date: 2026-10-26. Scope: read-only CLI checks and pinned-source inspection. **T6 remains blocked.** The planned v1.49.0 binary exists and its published asset digest verifies, but its completion status does not prove successful execution. Upstream hooks do not establish mandatory interception or output masking. The execution worker must remain disabled pending an approved, verified integration contract.

## Artifact provenance

The official `block/goose` release API redirected to `aaif-goose/goose`. Metadata came from the [v1.49.0 release API](https://api.github.com/repos/aaif-goose/goose/releases/tags/v1.49.0), and source was fetched at the commit resolved by the [tag API](https://api.github.com/repos/aaif-goose/goose/git/refs/tags/v1.49.0).

| Field | Verified value |
| --- | --- |
| Release | [v1.49.0](https://github.com/aaif-goose/goose/releases/tag/v1.49.0), published 2026-09-03T19:34:26Z |
| Source commit | `71fc4be1ed729e26b1dc0a4466abdd03be548a53` |
| Host architecture | Darwin arm64 |
| Asset | [goose-aarch64-apple-darwin.tar.bz2](https://github.com/aaif-goose/goose/releases/download/v1.49.0/goose-aarch64-apple-darwin.tar.bz2) |
| GitHub asset ID / size | `543242140` / `80109813` bytes |
| Published archive SHA-256 | `b0d29c99b310cfd58281ea50be6287be461438689506d6d4e994e4b05332fddb` |
| Computed archive SHA-256 | Same; checked before extraction/execution |
| Extracted executable SHA-256 | `6bc711de29cd43bcf1e3ac7a3193b453dd0348068192947079c3cb871542319c` |

Downloads used HTTPS with normal certificate validation through system curl. Python's certificate validation initially failed; it was not disabled. The archive contained only `.` and `./goose`; only the regular executable was extracted, with mode `0700`. This verifies consistency with the GitHub-published asset digest, not an independent signature, reproducible-build claim, or source-to-binary attestation.

The temporary artifact directory is `/var/folders/3b/9571c77j0078bs3mpjrqcxj80000gn/T/sfactory-goose-1.49.0-x_bb7kz3`. It holds release/tag metadata, the archive, executable, help/version output, and inspected source. Temporary artifacts may expire; the metadata above supports retrieval. No global installation, configuration, account, or service was changed. The existing `/Users/bo/.local/bin/goose` still reports `1.0.16` after this audit.

## Executed checks

Only the extracted executable's `--version` and `run --help` were executed. Both exited zero with empty stderr; version was `1.49.0`. Each invocation had stdin disconnected, a 20-second timeout, a temporary working directory, and a fresh environment containing only `PATH=/usr/bin:/bin`, plus temporary `HOME`, `XDG_CONFIG_HOME`, `XDG_DATA_HOME`, `XDG_STATE_HOME`, and `TMPDIR`. No model request, login, recipe, extension, or live task was run.

The actual help confirms `--no-session`, `--text`, `--max-turns`, `--output-format {text,json,stream-json}`, `--provider`, `--model`, and `--no-profile`. The latter disables default extensions in favor of CLI-specified extensions; it is not evidence of a complete security boundary. Extension flags include `--with-extension`, `--with-builtin`, and `--with-streamable-http-extension`. `--container` runs extensions inside a specified container; this audit neither selects that architecture nor treats it as proof of the planned macOS Seatbelt isolation.

## Completion contract: semantic mismatch

The pinned [JSON structures](https://github.com/aaif-goose/goose/blob/71fc4be1ed729e26b1dc0a4466abdd03be548a53/crates/goose-cli/src/session/mod.rs#L137-L155) contain `messages` and `metadata`. `metadata.cost_usd` is optional and omitted when unavailable; token counts are also optional. There is no explicit turn-count field. Output uses pretty-printed JSON, not one JSON object per line.

The decisive issue is the [response loop and output construction](https://github.com/aaif-goose/goose/blob/71fc4be1ed729e26b1dc0a4466abdd03be548a53/crates/goose-cli/src/session/mod.rs#L1739-L1845): an agent-stream error cancels the stream, handles interruption, then breaks the loop. Cancellation also breaks the loop. Subsequent JSON output sets `metadata.status` to `completed` in both usage-lookup branches, and the function returns `Ok(())`. Stream JSON similarly emits a `Complete` event after this loop. This is source evidence of a false-positive status path, not a claim that every possible CLI failure exits zero.

The current local parser correctly rejects malformed JSON and unknown cost, but its accepted `completed` status and count of assistant messages cannot distinguish this upstream error path from successful task completion. Assistant-message count is also not verified as the CLI's turn metric. Requiring cost to be known should remain fail closed; absent cost must not silently become zero. Exit zero, `completed`, a `Complete` event, or some assistant text individually cannot establish the required success receipt. No live inference was used to manufacture acceptance evidence.

## Mandatory interception and masking: unproven

The pinned [hook documentation](https://github.com/aaif-goose/goose/blob/71fc4be1ed729e26b1dc0a4466abdd03be548a53/documentation/docs/guides/context-engineering/hooks.md#L244-L321) and implementation show these limits:

- `PreToolUse` can deny a selected tool call. `on_failure: block` covers runtime failures of selected actions; the default is allow. Invalid configuration can skip a plugin's hooks, and invalid matcher regex can skip a rule. Configuration failure is outside that runtime fail-closed setting.
- [No loaded pre-tool hook permits the call](https://github.com/aaif-goose/goose/blob/71fc4be1ed729e26b1dc0a4466abdd03be548a53/crates/goose/src/agents/state_machine/ops_toolcalling.rs#L115-L133). The [agent constructor uses an empty hook manager for subagents](https://github.com/aaif-goose/goose/blob/71fc4be1ed729e26b1dc0a4466abdd03be548a53/crates/goose/src/agents/agent.rs#L465-L472). These paths prevent assuming universal hook coverage without separately proving the enabled execution surface.
- Post-tool and before/after shell hooks are observational. The [post-tool wrapper returns the original processed result and retains its notification stream](https://github.com/aaif-goose/goose/blob/71fc4be1ed729e26b1dc0a4466abdd03be548a53/crates/goose/src/agents/state_machine/ops_toolcalling.rs#L237-L310). They do not provide a replacement-result API for masking before the model sees content. Hook-supplied denial reasons are themselves unredacted, so policy scripts must not place secrets there.
- The [Unix developer shell selects `GOOSE_SHELL`, otherwise bash when available, then sh](https://github.com/aaif-goose/goose/blob/71fc4be1ed729e26b1dc0a4466abdd03be548a53/crates/goose/src/agents/platform_extensions/developer/shell.rs#L140-L156). A PATH `sh` shim alone therefore does not intercept its default shell. Optional login-shell PATH resolution and [live output notifications](https://github.com/aaif-goose/goose/blob/71fc4be1ed729e26b1dc0a4466abdd03be548a53/crates/goose/src/agents/platform_extensions/developer/shell.rs#L798-L850) also need explicit coverage. Setting a shell override would cover only paths actually routed through that shell, not arbitrary extensions or other tools.

## Remaining gate evidence

Before enabling the worker, resolve and verify a positive terminal-result contract for this pinned release, cost accounting and turn semantics, mandatory enforcement across every enabled tool/subagent path, and masking of both final results and streamed notifications before model access. Also retain the outstanding separate-UID, Seatbelt, protected configuration, and private-network isolation gates. Choosing a wrapper, upstream patch, or restricted tool surface is an integration decision still to be made; this audit implements none of them.

This prerequisite establishes artifact identity and CLI syntax only. It does not pass T6, authorize deployment, or complete the end-to-end verification gates.
