# Pinned Goose terminal and factory-entry hardening

Candidate patch for upstream Goose v1.49.0 source commit
`71fc4be1ed729e26b1dc0a4466abdd03be548a53`. It changes CLI terminal handling and an opt-in factory-entry guard, plus legacy/alternate terminal-error branches in
`agent.rs`, `state_machine/ops_compaction.rs` and `ops_maxturns.rs`. Restricted macOS MCP startup also preserves the broker-owned process group and rejects extension initialization failures before inference. It is not automatically applied or installed.

The stock release reports successful completion after terminal provider errors and
SIGINT cancellation. This patch preserves the terminal error, reports JSON `error`,
suppresses the stream `complete` event on failure, and returns an error for a nonzero
headless exit. Generic/network provider errors retain their error type rather than
becoming ordinary assistant text. Credits exhaustion, refusal, max-turn exhaustion, and recovery-compaction failure also retain typed errors. The CLI interactive recovery exception is retained;
these two error messages use the existing typed-error representation. The terminal helper is
backported from [upstream commit 9949cf9](https://github.com/aaif-goose/goose/blob/9949cf926cd42f1d128b9991ed23a496ecace896/crates/goose-cli/src/session/mod.rs)
and includes a focused unit test. Upstream code is Apache-2.0 licensed; see its
[license at the pinned revision](https://github.com/aaif-goose/goose/blob/71fc4be1ed729e26b1dc0a4466abdd03be548a53/LICENSE).

Apply only to the exact source revision after verifying provenance:

```sh
git apply --check /absolute/path/to/0001-headless-terminal-errors.patch
git apply /absolute/path/to/0001-headless-terminal-errors.patch
```

Use explicit paths to an already installed compatible compiler and Cargo. Upstream's
`rust-toolchain.toml` requests 1.96.1; invoking rustup shims in this source directory
can initiate a toolchain download. Keep `--locked --offline`, a separate target/cache
directory, and no network access for the local verification build. The experimental
build uses `--no-default-features --features rustls-tls,disable-update`; it does not
establish equivalence with the full release feature set.

Run the upstream helper test and then the actual binary fixture:

```sh
/path/to/existing/cargo test --locked --offline -p goose-cli --bin goose \
  --no-default-features --features rustls-tls,disable-update \
  headless_terminal_failures_propagate_and_success_remains_valid
python3 docs/planning/clean-room/verification/goose_terminal_status_spike.py \
  --goose /absolute/path/to/patched/goose --sha256 VERIFIED_BINARY_SHA256 \
  --expect patched --summary /absolute/path/to/new-result.json
```

The fixture requires both success controls and rejects error/cancel false success in
JSON and stream JSON. Add `--suite high-risk` to require credits, recovery-compaction, max-turn, and refusal rejection, with both provider success controls. All provider requests use a local deterministic stub. See the
[verification report](../../../docs/planning/clean-room/verification/2026-10-27-goose-mcp-group-inheritance.md)
for actual build/test status and provenance. Neither this patch nor a `completed`
status proves complete billing, successful artifacts, mandatory tool interception,
worker isolation, or watchdog cleanup. Live execution remains disabled.

The files ending `-initial.patch`, `-high-risk.patch`, `-compaction.patch` and `-factory-entry.patch` are historical evidence only. They are alternative revisions and must not be applied sequentially. Apply only `0001-headless-terminal-errors.patch` to pristine pinned source.

Factory entry uses `run --factory-restricted --no-profile --no-session --text ...`
with explicit `GOOSE_STATE_MACHINE=0`. Missing/conflicting required settings,
bang/slash input, builtins, HTTP extensions and recipes fail before session creation.
The option is opt-in: a future trusted launcher must mandate it and pin the binary
and approved stdio adapter. It does not establish universal isolation or interception.
Ordinary interactive behavior is retained; an initial-prompt/EOF smoke passed before
and after the change. Full interactive UI and subagent execution remain untested.

On macOS, restricted stdio MCP adapters inherit the Goose process group. This requires
a protected launcher that directly owns that group and approved adapter command.
Ordinary Goose retains separate MCP groups. Tool roots creating new groups must still
be broker-owned; this change does not prevent arbitrary descendant escape. Restricted
extension initialization failures return a nonzero exit before any inference call.
