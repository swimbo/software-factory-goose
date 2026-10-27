# Continue from late Phase 9

Updated 2026-10-26. This supersedes the 2026-10-16 handoff's claim that implementation was complete. Preserve the existing five-crate workspace; do not restart Phase 1 or scaffolding.

## Current authority

- `restart-audit-2026-10-26.md`: restart and environment evidence.
- `phase-9-plan.md`: composite implementation tasks and hard gates, still open where runtime work is missing.
- `verification/2026-10-26-story-coverage.md`: preliminary mapping of every story and integration scenario to actual code/proof.
- `decisions/2026-10-26-operator-auth.md`: three-reviewer debate and user resolution of O4: **separate local operator account and action-bound approval channel; no MFA claim**.
- `progress.md`: verification history. Earlier 31/61/101-test statements are snapshots, not current completion evidence.

Current local checkpoint: **135 tests passed,0 failed,0 ignored**, with all targets/features and locked offline dependencies; fmt, Clippy, build, doctests and setup fixtures passed. Logs are `verification/2026-10-26-*-final.log`. These are component gates only.

## What works at the tested component boundary

The workspace has a qualifier, dependency DAG, strict subprocess supervision and receipt parsing, command policy/masking shim, real exact-commit Cargo verification under macOS Seatbelt, bare-repository compare-and-swap promotion helper, default-deny budget/gateway logic, projection helpers, AST edges, Unix peer authentication and action-bound approval modules. See saved command logs for the exact tested revision and feature set.

The control-plane HTTP API is explicitly a diagnostic, in-memory model. Dispatch, result callbacks, approvals, credential issuance, budget raises and stop return unavailable until their authority paths are connected. The worker refuses Goose execution until its isolation, protocol and mandatory interception prerequisites are verified. There is no environment variable that bypasses these guards.

## Next implementation sequence

1. Finish authoritative Restate lifecycle/claim/lease/attempt/cooldown ownership, worker fencing, durable pipeline cascade and outbox production/relay/rebuild. The new standalone journals must not be registered on ordinary unauthenticated ingress.
2. Connect the worker queue and disposable worktrees under distinct identities. Verify a compatible pinned Goose binary side by side; installed `/Users/bo/.local/bin/goose` reports **1.0.16**, while the planning baseline is 1.49.0. Do not overwrite the operator's global binary/configuration.
3. Enforce the mandatory per-call budget route with conservative token/cost bounds, daily aggregate accounting and the actual external Bifrost contract. No inference has been authorized by a synthetic gateway test.
4. Provision and verify the separate service/operator/generator/evaluator identities and protected operator socket. Connect per-request authenticated identity, authoritative evidence eligibility, immutable approval issuance/consumption and replay-safe consequential execution. Keep the independent brake separate; implement the watchdog and scoped credential broker.
5. Implement the private holdout store/scenario runner and feedback path, then prove generator denial and exact-revision promotion. Model vote thresholds are a pre-filter; the controlling consensus requires deterministic checks and human authority.
6. Complete INT-01 through INT-12 and INT-LOOP with actual runtime evidence. Perform the enterprise, delivery, full plan-gap and Done-Means-Done gates only after their prerequisites pass.

## Local verification commands

From `clean-room/`:

```sh
cargo fmt --all -- --check
cargo test --workspace --all-targets --all-features --locked --offline
cargo clippy --workspace --all-targets --all-features --locked --offline -- -D warnings
cargo build --workspace --all-features --locked --offline
```

Offline commands use the existing lockfile and local cache. A cache miss is an environment failure, not permission to remove a dependency or weaken a test. Evaluator isolation tests require macOS Seatbelt; Linux isolation remains unimplemented.

The isolated projection example uses an explicitly selected disposable loopback database named `sfactory_verification`; its passing migrations/dedup/vector fixture is not Restate crash/replay proof. The operator socket example is diagnostic-only and does not activate factory mutations.

## Runtime boundaries

Do not run the old handoff's background startup or dispatch commands. Use `clean-room/setup.sh` usage and its setup documentation for preflight, infrastructure and registration checks. No live factory startup is proven. External Bifrost credentials, Restate deployment compatibility/private ingress, OS identity separation, independent watchdog and holdout permissions must be verified before activation.

No existing services, global Goose install, OS identities or gateway configuration were changed during this audit. The PostgreSQL verification container was disposable and was removed with its anonymous data volume.
