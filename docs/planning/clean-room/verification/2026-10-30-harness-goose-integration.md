# Phase 11A — actual protected Goose canary and live admission audit

**Phase incomplete. Candidate disabled. Live benchmark: 0/120.**

## Verified local integration

Pinned patched Goose 1.49.0 (`512bc701fca7312be12ae03215a41a0a60fae0848e2c39f167b7f79e510658fb`)
completed six protected macOS ARM64 cases through its real stdio MCP path:

| Case | Model-visible outcome | Independent observation |
| --- | --- | --- |
| Brokered read batch and ordered write | executed | Fixed authorized marker contains AUTHORIZED |
| Unknown capability | refused | Marker absent |
| Synthetic secret produced by tool | executed, masked | Key absent from every captured provider request; REDACTED result present |
| Model-supplied workdir override | refused | No marker |
| Model-supplied outside-write path | refused | No marker |
| Lazy schema discovery | executed | Only requested optional schema returned |

Every case advertised exactly `factory__run_script` and
`factory__fetch_tool_schema`, made exactly two **synthetic** provider requests,
completed without timeout, denied non-loopback egress, and independently denied
writes to the protected adapter code. Machine receipt:
`2026-10-30-harness-goose-integration.json`. These 12 synthetic calls are not live
benchmark attempts, model-quality evidence, independent task acceptance or bills.

The worker-side adapter forwards bounded JSON to a separate trusted fixture broker.
The QuickJS host and Rust normalizer run under that broker, outside Goose's sandbox;
QuickJS applies its own required containment. An initial direct nested-sandbox probe
failed closed on macOS. Starting a second sandbox inside the already sandboxed MCP
process is therefore not used as the canary architecture.

Two integration defects were found and corrected without model calls: isolated
Python (`-I`) omits script-directory imports, so the protected adapter explicitly
loads its own protected directory; real Goose sends MCP `_meta`, which is accepted
as protocol metadata and never passed as execution authority. Init failures made
zero provider calls. Original private failure receipts remain in /tmp; they are not
rewritten as passing results.

`harness_mcp.py` has a fixture-only CLI. It cannot select a live provider, read a
credential, install a production registry, choose a model-supplied working directory
or register the candidate. The library `serve(session)` requires its caller to
provide the protected authorized session. Cancellation/EOF tests exercise the actual
isolated stdio adapter process and verify remote cancellation and result suppression.
This same-UID macOS canary does not prove provisioned Linux peer identities, root
scope binding, production registry admission or daemon-independent cleanup.

Reproduce with existing reviewed binaries, without installation:

```sh
python3 clean-room/crates/execution/harness/goose_harness_probe.py \
  --goose /absolute/reviewed/patched/goose \
  --host /absolute/contained/script-host \
  --normalizer /absolute/sfactory_normalize \
  --summary /private/new-canary-receipt.json
```

## Current live blockers — read-only NUC verification

The existing factory virtual key is active. It currently has no attached key-level
budget rows. Exact local price rows for the two tagged DeepSeek routes are absent.
These observations alone do **not** prove that no cost calculation exists or impose
a new key-level-budget requirement: some historical factory Flash logs have costs.

The material gates remain unsatisfied:

1. `gateway.rs` requires reviewed aggregate price/token maxima and currently admits
   text-only nonstreaming payloads. The atomic inference/conversation modules are
   unregistered fixtures, not the sole authenticated task/daily authority for general
   Goose conversations. The protected deployed relay still has an exact two-turn
   write-files contract. It was not widened or bypassed for this benchmark.
2. The actual `auto` classifier configuration can add embedding and Luna fallback
   calls. Both count toward budgets; neither its 2s/6s timeouts nor session caching
   establishes a billable-token/retry ceiling. The existing contract does not cover
   all those calls plus the answer under the non-resetting $0.75 task cap.
3. Historical factory chat logs have missing cost entries, the classifier Luna row
   has no cost, and no linked classifier children were found for factory request IDs.
   Gateway estimates/partial costs are not complete trusted billed-cost receipts.
   Token usage and public-price multiplication cannot fill `billed_microusd` honestly.

The old monetary waiver was explicitly for the named October 28 INT-LOOP. It is not
applied to this benchmark. This work made no new waiver, credential issuance, budget raise, route
change, live inference, service restart, deployment, generation reset or promotion.
Existing unknown fences, active unrelated workers and root-finalization work remain.

To admit the 120 fresh paired attempts, establish the sole authenticated generalized
conversation authority, reviewed classifier/fallback/answer bounds and correlated
trusted billed receipts. Preserve existing reservations and daily scope. Then collect
independent task acceptance for the frozen suite and run the unchanged performance
gate. Current machine state: `2026-10-30-phase11a-benchmark-status.json`; evaluating
zero receipts fails `incomplete_pairs`, never enables the candidate or closes Delivery.

## Review and verification of final source

Actual ce-code-review completed with ten lenses and an independent validator:
`/tmp/compound-engineering-501/ce-code-review/phase11a-mcp-20261030-review/review.json`,
status complete, Ready with fixes. Both confirmed findings were fixed inline:
#1 checks the decoded alpha output and exact requested schema; #2 validates the
initialize protocol version and cancels/joins active work on every dispatcher exit.

The caller also reproduced and fixed incomplete HTTP acceptance: valid JSON with
a Content-Length 25 bytes too large must be refused, not accepted as executed.
Responses now require unique complete length framing. Notification-only cancellation
is checked while stdin stays open, separately from EOF. Subsequent calls on a closed
attempt receive a fixed refusal. An exceptional declarations failure with active work
also verifies remote cancellation and no result/traceback disclosure.

Final scoped suite: **38 passed**, Ruff and formatting checks passed. The final
actual-Goose six-case canary passed on the source hashes recorded in its JSON.
A real-Goose negative control changed the read callback to CORRUPT beta: the old
oracle incorrectly passed; the corrected oracle rejects it despite successful
execution and the authorized marker. Private red/negative receipts are retained
under /tmp/sfactory-phase11a-oracle-*; they never count as model-quality evidence.
No actionable source-review finding remains unresolved in this milestone.

A concurrent commit (`46dd8a8`) picked up the initial staged adapter/probe/test files.
History is preserved. The reviewed corrections and evidence are a follow-up source
milestone; no concurrent Root-finalization work is folded into those corrections.
The existing progress tracker was already under concurrent edits, so this dated
receipt records the Phase11A continuation without overwriting that work.
