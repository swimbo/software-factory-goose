# Operator approval issue reconciliation — 2026-10-27

Local synthetic Unix-socket fixture only. After a durable journal issues and stores an approval, a corrupt or mismatched issue response is an unknown outcome. The adapter now returns the generated nonce with `approval_outcome_unknown` for every post-issue validation, clock, or presentation failure, permitting an authenticated operator to inspect that exact record. It does not treat the response as permission to execute.

The test `corrupt_issue_reply_retains_nonce_for_status_reconciliation` deliberately stores a valid record then returns a corrupted response. Before the change it failed: code was `approval_state_unavailable` and the nonce was absent. It asserts a 503 unknown outcome, canonical nonce, successful exact-nonce status lookup, one issue, zero consumes, and `execution: not_executed`.

This is a same-account test fixture with an in-memory journal. It does not establish deployed separate-principal ingress, human presence, MFA, authoritative state provenance, durable exclusion, or exactly-once external execution. Approval and promotion must remain gated on those separate controls.

After the fix, `cargo test --offline --locked -p control-plane --all-features --lib operator_adapter::tests::` passed all 11 operator-adapter tests, and `cargo clippy --offline --locked -p control-plane --all-targets --all-features -- -D warnings` passed.
