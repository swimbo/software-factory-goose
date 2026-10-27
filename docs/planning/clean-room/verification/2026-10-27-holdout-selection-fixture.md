# Holdout selection binding fixture — 2026-10-27

Scope: local evaluator fixture only. No service was registered, no account provisioned, and no production resource activated.

`EvaluationSelection` holds a non-serializable selection for task, repository, target ref, base and candidate revisions, manifest SHA-256 and nonzero generation. `run_selected_fixture` checks the manifest digest and passes the selected candidate revision to the existing exact-revision runner. `bind_report` requires an equal caller-supplied current selection and matching candidate and manifest digest in the report. It returns a typed binding; generator feedback remains the prefilter's opaque feedback only. The selection configuration is explicitly trusted input, not a credential or authority.

Verification on the local macOS checkout, Cargo offline and locked:

- `cargo test --offline --locked -p evaluator --test selection`: **3 passed**. Checked malformed configuration, changed task/repository/ref/base/candidate/manifest/generation, mismatched report revision/digest, and serialized rejected feedback without internal binding values. Initial test-first run failed because the selection API did not exist.
- `cargo test --offline --locked -p evaluator --test selection --test holdout_runner`: **3 selection and 10 runner tests passed**. The selected runner exercised a temporary Git repository and real local Seatbelt fixture; a substituted manifest was refused, and the pinned one ran. The selected-runner API test initially failed to compile before implementation.
- `cargo test --offline --locked -p evaluator --test holdout_runner selected_runner_uses_pinned_manifest_and_candidate`: **1 passed** after adding a mismatched candidate-revision negative control.
- `cargo clippy --offline --locked -p evaluator --all-targets --all-features -- -D warnings`: **passed**, including the final selection API.

These tests do not prove authoritative manifest selection. No protected task registry or trusted candidate-path resolution supplies the selection; callers can construct both snapshots and the positive fixture deliberately passes the same one twice. Equality does not provide a fresh authoritative read, prevent concurrent mutation, or make evaluation and promotion atomic. The result is not persisted or connected to an authorization decision. Separate store/evaluator/generator principals, generator denial, listener lifecycle, containment, recovery, and end-to-end execution remain unverified and must remain closed until their own gates pass.
