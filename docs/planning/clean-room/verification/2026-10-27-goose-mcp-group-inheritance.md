# Restricted Goose MCP process-group inheritance

Date: 2026-10-27. Pinned source commit `71fc4be1ed729e26b1dc0a4466abdd03be548a53`. Offline fixture only; production worker remains disabled.

## Reproduced boundary failure

The preceding restricted candidate (`3add8f27a0a2b38c5b9ff10fb3a85e95affe842590c70413c5e7901cc3b1b8b1`) puts its MCP adapter in a separate process group. Pinned `extension_manager.rs::child_process_client` calls `spawn_long_lived_mcp_subprocess`, which invokes `configure_subprocess`; its common Unix setup calls `process_group(0)`. The watchdog fixture detected actual Goose/adapter group mismatch and refused before tool execution. Goose nevertheless returned zero after the failed extension initialization. Group mismatch refusal and Goose terminal status are separate assertions.

## Narrow patch

`--factory-restricted` now passes an explicit session-builder boolean into a per-agent extension-manager setting, enabled before extension loading. Only that restricted macOS stdio MCP path uses the transport builder directly, preserving the launcher's process group. Other platforms reject this restricted spawn path. Generic `configure_subprocess` and ordinary Goose spawning are unchanged. No model text, user configuration or inherited environment can independently enable this setting.

The restricted session gate returns an error if any requested extension fails initialization, before provider inference. The diagnostic is generic rather than echoing untrusted subprocess stderr. Ordinary extension loading retains its existing behavior. This is a trusted-launcher contract: the launcher must mandate the verified binary and restricted flag, own its process group, and supply protected configuration and approved stdio commands. Inheritance itself does not authenticate the launcher or establish containment.

## Verification

The candidate binary SHA-256 is `512bc701fca7312be12ae03215a41a0a60fae0848e2c39f167b7f79e510658fb`. The existing absolute Rust 1.98 toolchain built it with `--locked --offline`, disabled network access and writes confined to the task directory. Build exit was zero after 4m45s, with the previously recorded Xcode-cache, compact-unwind and optional-strip warnings. All seven original files matched the verified pinned source archive; applying the patch to pristine originals reproduced the prepared source exactly.

| Independent candidate regression | Result |
| --- | --- |
| [Restricted entry controls](2026-10-27-goose-mcp-group-entry.json) | 14 passed |
| [Basic terminal cases](2026-10-27-goose-mcp-group-terminal.json) | 6 passed: success, provider failure and cancellation in both output formats |
| [Real protected MCP adapter](2026-10-27-goose-mcp-group-boundary.json) | 6 passed, including command refusal and model-bound output masking |
| [Ordinary interactive smoke](2026-10-27-goose-mcp-group-interactive.json) | Initial prompt and EOF passed |

The independent [broker lifecycle fixture](2026-10-27-goose-broker-lifecycle.json) passes four cases on this candidate: explicit initialization refusal exits one before provider/tool calls; normal execution returns the exact synthetic nonzero exit and stdout/stderr; an unknown tool alias is refused; and the independent brake removes the five observed fixture processes across three broker-owned groups while the worker, adapter and tool are suspended. Actual adapter group IDs match the Goose group in restricted runs. The [ordinary-mode control](2026-10-27-goose-broker-ordinary-control.json) confirms Goose still creates a separate MCP group without the restricted option. See the [lifecycle report](2026-10-27-goose-broker-lifecycle.md) for exact ownership and cleanup limits.

The first normal copied-wrapper attempt used nonexistent `/bin/true` as its unused execution placeholder. The adapter correctly rejected that configuration; the fixture uses existing `/usr/bin/true` after correction. This was a fixture defect, separate from the previously reproduced zero-exit initialization failure. The explicit [initialization red result](2026-10-27-goose-broker-init-red.json) preserves the preceding candidate's exit zero and provider request after refusal; the [group negative control](2026-10-27-goose-broker-group-negative.json) preserves its separate adapter group.

[Provenance](2026-10-27-goose-mcp-group-provenance.json) records the preserved candidate, build, patch and evidence hashes.

## Limits

The adapter may share the broker-owned Goose group; any tool root that deliberately creates a new group must still be directly spawned and owned by the broker. No numeric PID registration is introduced. This patch does not prevent arbitrary process-group escape, provide distinct OS identities, secure all hooks/extensions, prove universal subagent exclusion, or enable the production worker. Ordinary interactive UI remains outside the bounded smoke coverage. The full upstream Cargo test suite remains blocked by the previously recorded uncached test dependency; the build uses only existing cached dependencies and a compatible installed compiler.
