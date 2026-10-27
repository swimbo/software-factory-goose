# Research brief — Goose/Rust harness reviewer

Researched 2026-10-27. Decision: which bounded integration experiment can establish mandatory tool mediation and truthful completion while preserving Goose, Rust, external Bifrost, and the planned macOS isolation? No implementation or activation is recommended as already proven.

## Evidence summary

1. **The pinned artifact is identifiable.** v1.49.0 was published 2026-09-03 and resolves to `71fc4be1ed729e26b1dc0a4466abdd03be548a53`. Its official arm64 archive digest matched before isolated help/version execution. This establishes artifact provenance, not task safety. [Release](https://github.com/aaif-goose/goose/releases/tag/v1.49.0); [local audit](../../verification/2026-10-26-goose-protocol.md).

2. **Pinned completion status is unsound for receipts.** After an agent-stream error or cancellation, the loop can emit JSON with hardcoded `completed` and return `Ok(())`. Cost is optional. Some assistant messages plus known cost do not repair the terminal-state ambiguity. [Pinned response processing](https://github.com/aaif-goose/goose/blob/71fc4be1ed729e26b1dc0a4466abdd03be548a53/crates/goose-cli/src/session/mod.rs#L1739-L1845).

3. **Restricted extension loading has real source support, with a resume exception.** `collect_extension_configs` uses an empty configured list under `no_profile` and skips plugin MCP discovery; explicit CLI extensions remain. The `resume` branch precedes this condition. A fresh-session-only factory launcher is therefore a credible experiment, while arbitrary resume is not. [Builder](https://github.com/aaif-goose/goose/blob/71fc4be1ed729e26b1dc0a4466abdd03be548a53/crates/goose-cli/src/session/builder.rs#L568-L625).

4. **No-profile is not no-hooks.** The agent separately loads hooks from current-directory plugin discovery. Discovery searches `.agents/plugins`, defaults unlisted plugin names to enabled, and prioritizes local/project settings before user settings. This is a distinct command-execution surface even when only factory MCP tools are advertised. [Agent constructor](https://github.com/aaif-goose/goose/blob/71fc4be1ed729e26b1dc0a4466abdd03be548a53/crates/goose/src/agents/agent.rs#L465-L472), [hook loading](https://github.com/aaif-goose/goose/blob/71fc4be1ed729e26b1dc0a4466abdd03be548a53/crates/goose/src/hooks/mod.rs#L424-L453), [plugin discovery](https://github.com/aaif-goose/goose/blob/71fc4be1ed729e26b1dc0a4466abdd03be548a53/crates/goose/src/plugins/discovery.rs#L154-L183).

5. **Dispatch contains useful defense, not universal proof.** Tool requests are filtered against names advertised for their inference and known extension tools. Messages without inference metadata take a compatibility allowance. Do not describe that conditional check as an immutable process-wide allowlist. [Advertised-tool check](https://github.com/aaif-goose/goose/blob/71fc4be1ed729e26b1dc0a4466abdd03be548a53/crates/goose/src/agents/state_machine/ops_toolcalling.rs#L678-L713), [known-tool filter](https://github.com/aaif-goose/goose/blob/71fc4be1ed729e26b1dc0a4466abdd03be548a53/crates/goose/src/agents/state_machine/ops_toolcalling.rs#L831-L861).

6. **Hooks cannot supply the required result boundary.** Missing pre-tool hooks allow; subagent construction uses an empty hook manager; the post-tool wrapper returns the processed result unchanged and retains notification streams. The documented `on_failure:block` excludes configuration-load failures. [Pinned hooks and tool wrapper](https://github.com/aaif-goose/goose/blob/71fc4be1ed729e26b1dc0a4466abdd03be548a53/crates/goose/src/agents/state_machine/ops_toolcalling.rs#L115-L310), [hook contract](https://github.com/aaif-goose/goose/blob/71fc4be1ed729e26b1dc0a4466abdd03be548a53/documentation/docs/guides/context-engineering/hooks.md#L244-L321).

7. **A sh shim is not comprehensive.** Developer shell selects `GOOSE_SHELL`, otherwise bash when available, then sh. Shell output also has live notifications. Both strengthen the case for owning the full tool result transport rather than relying on a PATH filename. [Shell selection](https://github.com/aaif-goose/goose/blob/71fc4be1ed729e26b1dc0a4466abdd03be548a53/crates/goose/src/agents/platform_extensions/developer/shell.rs#L140-L156), [notifications](https://github.com/aaif-goose/goose/blob/71fc4be1ed729e26b1dc0a4466abdd03be548a53/crates/goose/src/agents/platform_extensions/developer/shell.rs#L798-L850).

8. **Current upstream has a narrower terminal-error fix.** Official latest release API reports v1.56.0, published 2026-10-23, commit `9949cf926cd42f1d128b9991ed23a496ecace896`. Its source derives terminal errors from stream error, cancellation, and last-message error, emits JSON `error`, and returns the terminal error. That is evidence for a fix/backport candidate, not proof of cost completeness or mandatory masking. No new binary was executed. [Release API](https://api.github.com/repos/aaif-goose/goose/releases/latest), [pinned newer source](https://github.com/aaif-goose/goose/blob/9949cf926cd42f1d128b9991ed23a496ecace896/crates/goose-cli/src/session/mod.rs#L1558-L1679), [helper](https://github.com/aaif-goose/goose/blob/9949cf926cd42f1d128b9991ed23a496ecace896/crates/goose-cli/src/session/mod.rs#L2705-L2726).

## Option matrix

| Option | Support and fit | Main limitation |
| --- | --- | --- |
| Restricted factory-owned MCP on v1.49 | Best initial experiment; existing fresh-session loading supports a small tool surface | Project hooks, secondary paths, startup failures, and truthful terminal result remain unproven |
| Narrow pinned patch | Can explicitly disable discovery and carry typed terminal errors; preserves Goose | Owned maintenance and full result/notification coverage must be demonstrated |
| Rust library integration | Potential direct control over agent events and configuration | Larger integration surface; no stable embedding contract verified here |
| Newer pinned release | v1.56 source materially improves headless error handling | Separate version decision; does not establish the tool or masking boundary |

## Proof gaps and smallest spike

Use an offline deterministic provider fixture, factory MCP fixture, and recording sink; no external inference or credentials. Inventory every advertised tool, then return forged developer, extension-manager, subagent, and unknown tool calls. Confirm no forbidden sentinel action occurs. Place a project hook plugin in the fixture worktree and assert it never executes. Test fresh session, attempted resume, plugin changes, malformed configuration, and missing factory extension.

Send synthetic secrets through stdout, stderr, MCP error data, structured content, resources, notifications, and cancellation paths. Assert recorder input never contains the canary and bounded policy rejection reaches the model. Script transport failure, cancellation after partial assistant output, missing cost, repeated tool calls, and success; only the last case with complete accounting may produce a candidate receipt. Independently bind the resulting candidate SHA to wall verification and human promotion.

Preliminary recommendation: **ADEQUATE evidence for this bounded spike; INSUFFICIENT for enabling workers.** Start with a restricted factory transport and explicitly test the independent discovery surface. If protection requires a patch, keep it narrow and upstream-derived where possible. Do not infer success from flags or a newer version number.
