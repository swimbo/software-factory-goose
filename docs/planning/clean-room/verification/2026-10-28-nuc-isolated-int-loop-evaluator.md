# Isolated INT-LOOP evaluator

The host retains all expected challenge results. Each challenge gets a fresh durable two-root Batch; only its executor runs, under UID1001 in a network-none, read-only, cap-dropped container with a read-only candidate snapshot. It receives only one fixed host-selected command through the bounded execution adapter. It never receives the host evaluator source, key, `.git`, relay socket or result authority. The host checks actual status/stdout/stderr, then requires exact-root cleanup and the fixed worker slice empty before another challenge or any result publication.

An independent user systemd unit owns the evaluation. ExecStopPost reconciles every recorded challenge family on normal exit or controller death. The launcher retains its exact unit and private root on uncertainty, never retries a challenge, and requires a teardown receipt before importing the immutable evaluated blobs into the separately protected Git repository. Finalization rechecks the committed blobs against evaluated hashes. Candidate tests are additional evidence; a self-reported unittest count is not proof of their quality.

## Actual NUC controls

`python3 /tmp/sfactory-tool-relay-code.f6O9xEoS/nuc_int_loop_evaluator_spike.py` passed:

- A known constant-output fixture passed its default greeting but failed the named challenge. No evaluation result was published; all owned roots were removed and the fixed slice was empty.
- A sleeping candidate was executing when the exact unit main was SIGKILLed. ExecStopPost removed the owned roots, observed the fixed slice empty and withheld evaluation success.

Raw output: `2026-10-28-nuc-evaluator-controls.log`. Private retained control evidence roots: `/tmp/sfactory-eval-negative-96gpbujl`, `/tmp/sfactory-eval-ownerloss-8awqr_ej`.

Four local task controls reject constant output, altered evaluated bytes, the same incorrect output under optimized Python, and a mutation between digest checking and Git staging. The last control creates a rejected commit but withholds the accepted evaluation artifact because committed bytes differ.

## Limits

These are scoped fixture controls, not production holdout provisioning or host/daemon-loss proof. Trusted host operators serialize this fixture's fixed slice; it is not a multi-tenant scheduler. The first actual Bifrost attempt was rejected before any tool/candidate release and its dispatch remains unknown; this report claims neither a successful live candidate nor INT-LOOP completion. Live generation, exact artifact evaluation and action-bound promotion remain separate required evidence.
