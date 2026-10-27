# Legacy type shapes

`legacy-shape/v1` contains draft-07 schemas generated from the current shared
`Receipt`, `Claim` and `CredentialGrant` serde types. The version identifies
this schema snapshot only; these messages have no version field and this does
not establish a new wire contract. They are not registered in any runtime or
an authoritative production validation boundary.

These shapes do not bind a receipt to a claim, attempt, stage or exact revision.
They do not validate authorization, lease liveness, replay, approval, secret
handling, or other business rules. Successful shape validation does not imply
that any operation is safe. JSON Schema and serde can disagree on edge cases
such as numeric representation, integer ranges or date formats; consumers must
not assume equivalence without their own validation.

Regenerate from the Rust types with `cargo run --locked --offline -p shared
--example contract_schemas` from the workspace root. Review schema diffs and
run `python3 crates/shared/tests/legacy_schema_parity.py` using a Python with
`jsonschema` installed after building the `check_legacy_contract` example.
The parity test is a bounded corpus, not a proof of equivalence.
