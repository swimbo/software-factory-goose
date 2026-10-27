# Pinned Goose terminal-status backport

Historical first-patch evidence; the [extended terminal-path report](2026-10-27-goose-terminal-high-risk.md) supersedes its coverage and current patch. Temporary build output paths may now contain the expanded binary; use the recorded digest to identify each tested revision.

Date: 2026-10-27. Scope: a local candidate patch and offline terminal-status verification; no factory activation or global Goose replacement.

## Defect reproduced before modification

The digest-verified stock Goose v1.49.0 binary reported success after both a deterministic provider failure and SIGINT cancellation after partial assistant output. Each failure exited zero and either emitted JSON `metadata.status = completed` or a stream JSON `complete` event. The two ordinary success controls also passed. The local provider received four requests in each error case because of upstream retries; there was no external inference.

The [baseline evidence](2026-10-27-goose-terminal-status-baseline-confirmed.json) includes all six cases, request counts, output hashes, binary hash, fixture hash, and temporary raw-output paths. The test requires the injected error or partial-output marker to appear, so the negative cases cannot pass without exercising their stimulus. An earlier [baseline capture](2026-10-27-goose-terminal-status-baseline.json) records the same behavior before that additional assertion was added.

## Minimal patch

[initial patch](../../../../clean-room/patches/goose-1.49.0/0001-headless-terminal-errors-initial.patch) changes two upstream files: CLI `session/mod.rs` and two provider-error branches in `crates/goose/src/agents/agent.rs`, against exact source commit `71fc4be1ed729e26b1dc0a4466abdd03be548a53`.

The patch retains stream errors, derives a terminal error from headless cancellation or the last error-bearing message, emits JSON `error`, suppresses stream `complete` on failure, and returns the terminal error. The CLI interactive recovery exception and normal successful completion are retained; generic/network provider failures now use the existing typed error-message representation. A focused helper test covers stream error, message error, cancellation, success, and the interactive exception.

The first one-file backport fixed cancellation but still accepted provider failures in both JSON formats. The [failed intermediate binary run](2026-10-27-goose-terminal-status-incomplete-backport.json) demonstrated that v1.49 legacy provider branches turn errors into ordinary text. The final patch routes those two branches through the existing `Message::from_provider_error` constructor; it does not classify text prefixes as errors.

The CLI change is a narrow backport of the terminal handling already present in [upstream commit 9949cf9](https://github.com/aaif-goose/goose/blob/9949cf926cd42f1d128b9991ed23a496ecace896/crates/goose-cli/src/session/mod.rs), not a release upgrade or a new completion protocol. The [patch README](../../../../clean-room/patches/goose-1.49.0/README.md) describes application and licensing. `git apply --check` passed against the verified pristine source, and applying it produced byte-identical prepared source.

## Provenance and build boundary

The full source archive came from the official repository's commit-addressed HTTPS endpoint. Its SHA-256 is `7e90a3dc6b2bb18c8c343d36975e43ba2804b3bd3bd19d51e32ee31a01fb99b0`. All 763 build-source blobs under `crates`, `vendor`, and `.cargo`, plus Cargo manifests/lockfile/toolchain file, matched the previously recorded untruncated Git tree. The original session source blob is `a705e815b518e114ebaf85fb14363d4e0680c744`. [Machine-readable provenance](2026-10-27-goose-terminal-patch-provenance.json) records the source, patch, and local paths.

The local test build uses the already installed Rust 1.98.0 compiler and Cargo through absolute paths. It uses `--locked --offline`, a copied Cargo cache, an isolated HOME/TMPDIR/target directory, a scrubbed environment, and a Seatbelt profile denying network access and writes outside the temporary build root. Its explicit features are `--no-default-features --features rustls-tls,disable-update`; equivalence with the release's full feature set is not established.

Build preparation had two side effects before the final offline-only constraint: a `rustup toolchain list` invocation inside upstream's source directory unexpectedly obeyed its `rust-toolchain.toml` and began installing 1.96.1; the owned process was terminated, leaving partial Cargo/Clippy files without a rustc binary. That directory is preserved because prior ownership was not established. The default toolchain was not changed. An initial online `--locked` dependency fetch populated Cargo caches after the first offline attempt lacked the pinned ACP dependency; that process was stopped, and subsequent work uses only the copied cache and network-denied build. No global Goose binary or configuration was replaced.

## Verification

The [reproducible fixture](goose_terminal_status_spike.py) runs fresh protected sessions against a deterministic loopback provider. Before each case it verifies that an external TEST-NET connection receives `EPERM`. It verifies the supplied executable digest and v1.49.0 version. Both JSON and stream JSON are exercised with success, provider error, and cancellation after a partial response. `--expect baseline` requires reproduction of false success; `--expect patched` requires nonzero exit, a failure status/event, and no successful completion for the four negative cases.

The [final patched-binary run](2026-10-27-goose-terminal-status-patched.json) passed all six cases:

| Format | Stimulus | Exit | Terminal result |
| --- | --- | --- | --- |
| JSON | Success | 0 | `completed` |
| JSON | Provider HTTP 400 | 1 | `error` |
| JSON | SIGINT after partial response | 1 | `error` |
| Stream JSON | Success | 0 | `complete` |
| Stream JSON | Provider HTTP 400 | 1 | `error`, no `complete` |
| Stream JSON | SIGINT after partial response | 1 | `error`, no `complete` |

Each case passed the external-network denial probe and stimulus-visibility assertion. The final local binary SHA-256 is `d3650d37409e3e207ef1c69c8eb42ee66ff9584dfb91f404602f37b18f1cbaf4`. The final offline build exited zero. Build warnings included denied Xcode cache writes, a large compact-unwind section, and an optional `rust-objcopy` stripping failure caused by the existing toolchain's missing `libLLVM.dylib`; no global toolchain repair was attempted. The resulting binary ran all six cases successfully.

The exact patched helper and its included test were extracted unchanged, compiled with the existing compiler against the actual built Goose/anyhow libraries, and executed under the network/write sandbox: **one test passed**, covering five assertions (stream error, typed message error, cancellation, ordinary success, and interactive exception). [Helper test evidence](2026-10-27-goose-terminal-helper-test.json) records the source/binary/log digests and library paths. This is a focused standalone test, not the upstream Cargo test suite. The Cargo invocation was blocked by the isolated offline cache lacking `env-lock v1.0.2`; no dependency download was attempted after the offline-only constraint.

## Limits

This patch addresses the exercised generic provider-error and cancellation paths. Dedicated credits-exhausted, provider-refusal, compaction-failure, max-turn, and other legacy terminal paths are not covered by these fixtures and remain separate proof gaps. This is not universal terminal correctness. It fixes reporting only. It does not make cost mandatory, reconcile actual gateway spend, prove task/artifact success, change tool routing, mask provider errors, establish process-family ownership, enforce distinct UIDs, prohibit plugins/resume/alternate tools, or close any untested output path. A successful CLI completion still cannot substitute for the factory's independent receipt, evaluation, and promotion gates. Cancellation can occur after side effects; the status fix is not rollback or descendant-cleanup evidence. The live factory worker remains disabled.
