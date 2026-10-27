# Durable intake component — 2026-10-27

Scope: bounded G-07/R3 implementation. `intake.rs` supplies immutable versioned admission contracts; `intake_workflow.rs` stores them in an exclusive Restate virtual object. Both are exported from the control-plane library; the object remains unregistered. No worker/spike, endpoint, standing service or credential was changed.

## Contract

A client-generated canonical uppercase ULID is both the object/idempotency key and intent ID. First admission binds the full schema-versioned request (logical repository identifier, canonical full branch ref, full lowercase base revision, intent text, ordered acceptance criteria), configured submitter scope and journaled creation time. Identical retries return the original record without consulting the clock or rewriting state. Changing any request binding conflicts; another principal cannot take over the record; malformed stored bindings fail closed. No key TTL/reset method is implemented.

Request identity, lane/risk inputs, knowledge assertions, budgets, approvals and state cannot be injected through extra JSON fields. Repository identifiers are metadata, not caller-selected paths to read. The contract does not establish that the repository/revision exists or that criteria are executable. Every admitted record starts `awaiting_qualification`; this object does not dispatch tasks or grant privileged actions.

The constructor's submitter string is configuration only. It does not prove caller identity. Registration must wait for a private adapter that authenticates each request and binds the configured scope correctly. The adapter must enforce a raw request-body bound before deserialization; current typed validation bounds intent, criteria and total accepted text after deserialization.

## Test evidence

Test-first RED: `cargo test --locked -p control-plane intake:: --lib` failed with 26 missing type/function/constant errors before implementation.

GREEN:

- `cargo test --locked -p control-plane intake:: --lib`: initial 6 tests passed.
- `cargo test --locked -p control-plane --all-features intake --lib`: final 8 tests passed; 0 failed/ignored. This also compiled the new Restate object against installed SDK 0.12.1.
- `cargo clippy --locked -p control-plane --all-features --lib -- -D warnings`: passed.
- Scoped `git diff --check`: passed.

Cases cover original identity/time after serialization and clock change; changed schema/repository/ref/base/intent/criteria; distinct keys; principal takeover; forbidden payload authority fields; invalid key/schema/revision/ref/text; bounded payload lengths; reordered criteria; stored binding corruption; and the accepted/rejected canonical branch-reference subset.

## Limits and next integration work

The tests exercise pure first-write-wins decisions and SDK compilation. They do not prove concurrent delivery, lost acknowledgements or restart/replay against a live Restate server. Exclusivity relies on the virtual object's runtime semantics and still needs that integration gate.

The diagnostic HTTP submit path is unchanged and remains a memory-backed demonstration. There is no public/CLI intake adapter, trusted repository registry, grounded qualifier transition, task queue integration, intake outbox projection, enumeration/retention policy or lifecycle upgrade implementation. G-07 and G-01 remain partial, not closed. No production durability or activation claim is made.
