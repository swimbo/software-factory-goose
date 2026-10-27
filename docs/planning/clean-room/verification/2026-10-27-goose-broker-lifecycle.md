# Goose broker lifecycle verification

Status: bounded actual-Goose lifecycle and ordinary-mode isolation controls passed. No production activation or distinct-UID proof.

The watchdog's opt-in `fixture` feature now supports bounded, complete UTF-8 stdout/stderr and stdin from immutable synthetic catalogue entries. Registry ownership of `Child` and all wait/reap calls remains exclusive; reader threads receive pipes only. Natural exit still requires a group-stop attempt before reap and observed group absence before output release. Invalid UTF-8 or output above 1 MiB per stream withholds the complete result. `/result` exists only on the fixture broker router, and production admission rejects captured IO specs.

The reusable `broker_capture_fixture` example reads a private, owned local catalogue before binding private Unix sockets. It accepts no command, UID or PID admission over HTTP. The lifecycle harness copies the actual MCP protocol adapter and replaces only `run_worker` with one exact synthetic command-to-launch-ID mapping. This is a lifecycle prototype, not integration of execution policy, output masking or durable completion receipts.

## Verified

- All-feature watchdog tests: 12 unit + 6 integration passed. Default-feature tests: 8 passed. Strict all-feature/all-target Clippy passed.
- Actual shell stdout/stderr and exit 7 preserved; repeated launch returns the same receipt; natural exit is reaped only by registry. Invalid UTF-8 and 1 MiB + 1 byte output are withheld.
- Old restricted Goose SHA `3add8f27a0a2b38c5b9ff10fb3a85e95affe842590c70413c5e7901cc3b1b8b1`: actual MCP PGID differed from parent Goose PGID. Wrapper refused before any tool launch. Negative control passed; containment did not. [Evidence](2026-10-27-goose-broker-group-negative.json).
- Independent initialization refusal on that same binary reproduced Goose exit zero and one provider call after mandatory extension failure. The new assertion was red; no tool launched. [Evidence](2026-10-27-goose-broker-init-red.json).

Patched Goose SHA `512bc701fca7312be12ae03215a41a0a60fae0848e2c39f167b7f79e510658fb` passed all four lifecycle cases. [Exact result](2026-10-27-goose-broker-lifecycle.json):

| Case | Observed result |
| --- | --- |
| Initialization refusal | Exit 1, zero provider requests, zero tool launches. |
| Admitted synthetic tool | Actual MCP inherited Goose PGID; exact tool exit 7, stdout `VISIBLE_BROKER`, stderr `STDERR_BROKER` preserved through the real MCP protocol; both adapter and Goose absent afterward. |
| Unknown model command | `policy_denied` response; no tool process started. |
| Hung components | Worker, MCP adapter and tool leaders were confirmed suspended. Independent brake stopped all three owned groups; all five observed processes absent, direct leaders reaped, repeated stop identical. |

The same candidate retained ordinary MCP process-group isolation: actual adapter PGID differed from Goose, so the fixture wrapper refused before tool launch. Ordinary Goose still exits zero after extension warnings; that mode is not approved for factory use. [Ordinary control](2026-10-27-goose-broker-ordinary-control.json). The successful synthetic conversation after a nonzero/refused tool response is not a factory task-completion receipt.

Every actual-Goose run uses a private temporary root, scrubbed synthetic environment, deterministic loopback provider, private Unix broker, and macOS profile with an independently verified external-network denial. Final runs verified cleanup of their owned processes and removed their private roots. The harness cleans only its own processes and root. No user services, accounts, credentials or live provider were used.

## Reproduce

From repository root:

```sh
cargo build --locked --manifest-path clean-room/Cargo.toml -p watchdog --all-features --example broker_capture_fixture
python3 docs/planning/clean-room/verification/goose_broker_lifecycle_spike.py \
  --goose <reviewed-candidate-path> --sha256 <reviewed-candidate-sha256> \
  --broker clean-room/target/debug/examples/broker_capture_fixture \
  --summary <new-result-path>
```

Ordinary-isolation control adds `--ordinary --expect-group-refusal`. A single refusal case uses `--case init_refusal`. Default run requires initialization refusal to be nonzero with zero provider calls; preserved tool stdout/stderr/exit; unknown-command refusal; and stopping three broker-owned groups while worker, MCP adapter and tool are suspended. Actual PGID equality is required before any tool admission.

## Gates retained

Full production lifecycle remains blocked on a trusted claim/policy catalogue publisher, actual execution adapter integration, sealed launch authority, separate identities and both spawn/signal OS authority, escaped-descendant containment, and watchdog crash recovery. No numeric PID registration or external waiter is permitted. See the [reviewable OS authority path](2026-10-27-watchdog-os-authority-review.md).

Patch provenance and independent Goose regressions: [restricted MCP grouping review](2026-10-27-goose-mcp-group-inheritance.md). Initial normal-case harness startup failed because its unused dummy execution path `/bin/true` does not exist on Darwin; correcting it to `/usr/bin/true` required no adapter or Goose source change.
