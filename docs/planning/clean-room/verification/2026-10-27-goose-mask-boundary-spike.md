# Source-side masking at the recorded model boundary

Date: 2026-10-27. **Bounded reassembly followed by the repository's Rust masker prevented the synthetic key from reaching the recording provider in tested success, tool-error, and RPC-error paths.** Raw controls and deliberately incorrect per-chunk masking leaked the key. Notifications were observed in CLI output, not model requests; model-side notification coverage remains unexercised. This is an offline fixture result, not proof of mandatory production masking or T6/R14 closure.

## Artifacts

- [Reproduction script](goose_mask_boundary_spike.py), SHA-256 `6124c8cf6ebb3607261f6656e41a35ee868d827145346ca4ea490532e5ab37b4`.
- [Observed summary](2026-10-27-goose-mask-boundary-spike.json).
- [Exact model-bound tool messages](2026-10-27-goose-mask-model-messages.json), copied from recorder requests without changing message content. These contain deliberately synthetic control strings, never real credentials.
- The script imports the existing [base harness](goose_hook_spike.py) and [tool-capable recorder](goose_protected_config_spike.py).

```sh
python3 docs/planning/clean-room/verification/goose_mask_boundary_spike.py \
  --goose /absolute/path/to/audited/goose \
  --summary /absolute/path/to/new-evidence.json
```

Requires the audited Darwin arm64 binary, `rustc`, and an already-built local `clean-room/target/debug/deps/libregex-*.rlib`. It performs no dependency download. The script refuses a mismatched Goose binary digest or existing summary destination. It snapshots the actual `execution/src/mask.rs`, compiles a temporary helper against cached regex, and runs the module's five existing tests plus a split-boundary regression test. All six passed.

Mask source SHA-256: `89f97d1070a6ae5e0787692eae40b37cda460a7641f319ce27c081d54c84e9c0`. Helper executable SHA-256: `81729e1dd2091ff6ad430e09edc92c8f47aa6f541df54260ad65d1ac38c088db`. Goose executable SHA-256: `6bc711de29cd43bcf1e3ac7a3193b453dd0348068192947079c3cb871542319c`; observed version `1.49.0`.

## Fixture and positive controls

Each case had a fresh protected launch directory, isolated config/home/runtime paths, one fixed MCP tool, and the deterministic loopback provider. The provider requested `fixture__mask_probe`, recorded the subsequent tool-result message, then returned `OFFLINE_STUB_OK`. Every case made two provider requests, advertised exactly that one tool, exited zero without timeout, and delivered `VISIBLE_TOOL_SENTINEL` to the provider. These observations establish that the result path was exercised; absence of a key alone was not treated as success.

The fixed producer input was a fake provider-key-shaped string split into two fragments, `sk-OFF` and `LINE0123456789ABCDEFGHIJKLMN`. No real secrets were read or injected. The incorrect control masks each fragment separately and joins them afterward; neither fragment independently matches the provider-key pattern, so the reconstructed key leaks. The safe fixture joins this small, fixed-size input first, then invokes the real Rust masker before serializing MCP output. This demonstrates the reassembly requirement; it does not implement arbitrary streaming or an unbounded buffer.

The tool emits ordinary text results, `isError: true` text results, or JSON-RPC errors with both message and nested data. Notification cases emit a standard logging notification before a benign tool result. All source payloads are fixed by the fixture, not selected by model arguments. The source-side helper is invoked before the payload enters Goose; post-tool hooks are not used.

## Results

| Case | Key in provider request | Redaction in provider request | Interpretation |
| --- | --- | --- | --- |
| Raw successful result | yes | no | Recorder positive control |
| Incorrect per-chunk masking | yes | no | Split-key leak reproduced |
| Reassembled, masked success | no | yes | Exercised result path passed |
| Raw tool error | yes | no | Error-path positive control |
| Masked tool error | no | yes | Exercised error path passed |
| Raw RPC error | yes | no | RPC-error positive control |
| Masked RPC error | no | yes | Exercised message/data path passed |
| Raw notification | no | no | Notification absent from model path; raw key present in CLI |
| Masked notification | no | no | Notification absent from model path; CLI key absent |

The three masked result/error cases also contained neither synthetic fragment anywhere in the full recorded requests. Their visible sentinel and `[REDACTED]` survived, so this was replacement rather than simply suppressing the tool result. All request captures were inspected; the summary records a SHA-256 for each complete capture. The durable message file contains the exact tool-message subset, while complete system/user/tool request bodies remain in the temporary fixture directory.

For notifications, `VISIBLE_NOTIFICATION_SENTINEL` appeared in CLI stream output for both controls. The raw version included the fake key; the masked version did not. Neither notification sentinel appeared in provider requests. Consequently this experiment proves source-side sanitization on that observed CLI notification path only. It cannot prove how another notification type, extension, provider, or future version might enter model context.

## Isolation and limits

The fixture profile denied external network access and permitted only the loopback provider port; an `EPERM` external-connect probe was required before every case. It denied writes outside temporary runtime paths and denied reads beneath the actual user home. Environment values were explicitly constructed, telemetry/session naming disabled, and authentication/usage values synthetic. The HTTP server shut down in `finally`. No external inference, global configuration, factory service, or production masking source was changed.

Raw captures, helper binaries, snapshotted source, tests, and fixture files remain at `/private/var/folders/3b/9571c77j0078bs3mpjrqcxj80000gn/T/sfactory-mask-boundary-_nq5wrri`; temporary files may expire. Script syntax and evidence assertions passed. The frozen source and hashes distinguish this test from later masker changes.

Still untested: general structured/media/resource content, other notification types, arbitrary chunking and encodings, truncation/overflow, masking-helper failure, tool stderr, cancellation during output, bypass/alternate tools, process cleanup, real cost accounting, and production identity separation. The masker is a finite regex filter, not general DLP. This fixture does not make it mandatory for every enabled tool. A production boundary must reject unsupported content and establish fail-closed behavior on sanitizer failure before it can claim coverage.

Continue the restricted candidate with these explicit gaps. Keep live execution blocked; do not infer model-side notification safety from the absence of an exercised notification-to-model path.
