# Fixed failed-generation Unknown inputs

Actual NUC preparation passed for closed generation
`01M65RMR3F04YB1B016EBBSXGG`, task `01M65RMR3FE6FQTFRBHERRHXRG`.
This creates inputs only; it publishes no authorization and starts no service.

- Reviewed composed source: `5d1a688a1d402666321e7e2fd0502c12b817afcac40864248e76250189671dc4`.
- PLAN receipt: `/tmp/sfactory-identity-admin-uoisvbsk`.
- APPLY receipt: `/tmp/sfactory-identity-admin-j2st8s4u`.
- Root600 request SHA256: `909f22e751b7608461ea3ff8b8b9c89d362fbfbcae8328bbc317c7b720fb0c63`.
- Root600 runtime config SHA256: `4d6b9bfda3b46d6e3bffcb8592d77dd8c3c7b3c900e83fd8de2a4b94325c2ff3`.

The preparer reads protected grant, catalog, recipe and actual stop observation,
recomputes the full domain-separated binding and recipe digest, and checks the
fixed task/generation, current boot and observation cgroup identity. The request
records cleanup/outcome_unknown and explicit unknown spend. It does not infer
evaluation, completion, engine reconciliation or human approval.

The config uses the earlier protected runtime namespace values. Those are input
bindings, not current process attestation; a separately attested native finalizer
must validate its actual namespace and all fixed evidence before publication.
The Rust strict parser and UnknownCleanupVerifier remain authoritative. Pass/fail
evaluator provenance and production journal integration remain separate gates.

Three focused tests pass: unknown semantics and exact request hash, substitution
of root binding/recipe/observation/boot, and duplicate/nonfinite JSON refusal.
