# Preliminary story and integration coverage audit

Audit date: 2026-10-26. Scope: read-only review of implementation and existing evidence against `user-stories.md`, `e2e-tests.md`, and the Phase 9 checklist. This is **not Phase 13 completion**. Implementation is changing concurrently; this records the inspected source snapshot and must be reconciled after final wiring.

**Finding:** substantial tested components exist, but the requested factory vertical slice is not implemented end to end. No full user story should be reported as production-verified from the current unit/fixture evidence. Missing-knowledge routing is implemented at the local diagnostic API boundary. Runtime dispatch, worker execution, result callbacks and privileged operations currently fail closed rather than pretending to succeed.

## Evidence and interpretation

Current-tree update: [final all-target/all-feature test log](2026-10-26-tests-final.log) records **135 passed,0 failed,0 ignored**; separate doctest, fmt, Clippy, build and setup final logs also exit0. The older101-test log below is historical. These checks verify existing component specifications, not missing live scenarios.

- **P — passing component evidence:** [saved test log](/Users/bo/code/software-factory-goose/docs/planning/clean-room/verification/2026-10-26-tests.log) records 101 passing tests across its listed suites, including AST/Restate feature tests. This is an earlier snapshot: it does not contain the newer approval, transport or repository-knowledge route tests. [Saved clippy log](/Users/bo/code/software-factory-goose/docs/planning/clean-room/verification/2026-10-26-clippy.log) also predates those additions. Neither establishes current whole-tree cleanliness.
- **V — evaluator fixture proof:** the saved log and this session's scoped rerun pass 5 evaluator unit plus 8 integration tests. Actual Seatbelt fixture execution covers successful checks/tests, a real failing test, a type error, host read/write denial, loopback denial, committed-content scanning and exact bare-repository advancement. These are local fixture proofs, not a deployed generator/holdout wall.
- **U — transport fixture proof:** this session ran `cargo test -p control-plane --lib operator_transport`: 6 passed. Actual Unix connections provide kernel peer identity; configured UID mismatch and lookup failure are synthetic negatives. No separate operator/service accounts were provisioned or successfully exercised.
- **S — source/test present:** code or tests exist but the saved aggregate log does not establish their current passing state. This is weaker than P/V/U.
- **Missing:** no implementation/evidence satisfying the criterion was found in the inspected scope. **Partial:** some acceptance criteria have code or tests; at least one material criterion remains unmet.

The earlier test plan overstates the statistical role of 2-of-3/90% and automatic drift promotion. Consensus R2/R11 demotes the model run counts to a pre-filter and requires deterministic checks plus human promotion authority. Coverage must preserve that controlling decision instead of reinstating obsolete acceptance behavior.

## User story coverage

| Story | State and concrete evidence | Remaining acceptance gap / blocker |
|---|---|---|
| **US-1 Submit/lane** | **Partial, P/S.** CLI submit exists; `main.rs::submit_intent` returns decision ID, score, lane and reason; route tests exercise dark routing. | Stores only `QualifierDecision` in an in-memory map; original intent content is not durably retained/immutable. Every submit generates a new ID. No live CLI-to-durable-intake proof. |
| **US-2 Qualifier reasoning** | **Partial, P.** `qualifier.rs` implements four weighted factors, hard gates and reason; inspect returns stored decision. | Inspection now retains all four input factors in the diagnostic cache. Durable intake still does not retain immutable original intent/feature evidence; API uses provisional greenfield defaults. |
| **US-3 Knowledge prerequisite** | **Implemented at diagnostic boundary, P/S.** Pure missing-knowledge hard gate passes. New `main.rs::has_repository_knowledge` reads a nonempty bounded regular `AGENTS.md` from the selected repo; negative route test present. | New route test is not in saved aggregate log. Prove the selected repository is the same immutable repository/claim used at execution. No live worker dispatch is enabled. |
| **US-4 Stage visibility** | **Partial, P/S.** State and pipeline transitions, individual task lookup, projection/audit helpers and CLI status exist. | List endpoint now includes all pending/running tasks with pipeline spend and explicit null revision. Per-task spend/SHA and worker assignment remain unestablished. Audit helper is not called for every transition; in-memory state is not durable observability. |
| **US-5 Gateway/caps** | **Partial, P.** `gateway.rs::chat` checks the exact key's governance budget, requests an atomic Restate reservation before inference, and fails closed; local HTTP mock tests pass. | Goose is not wired through this mandatory choke point. No actual Bifrost/provider cost reconciliation or exclusively enforced network route is proved. |
| **US-6 Hidden holdouts** | **Missing runtime proof.** Evaluator Seatbelt host/network denial fixtures are V. | No holdout store or generator UID denial integration exists. Evaluator sandbox denial is not generator-to-holdout isolation. |
| **US-7 Triple-run evaluation** | **Partial, P.** `scenario_passes` and `aggregate_passes` arithmetic tests pass; deterministic Cargo verification is V. | No scenario runner, ephemeral deployment or three-run orchestration. Helpers now enforce exactly three runs, every scenario2-of-3 and aggregate90%. No loop-back execution. Apply consensus pre-filter semantics. |
| **US-8 Opaque feedback** | **Partial source.** `opaque_failure` constructs a scenario-name failure string. | No test of scenario-body non-disclosure through the actual evaluator→worker path; no live feedback path or private scenario storage. |
| **US-9 Human budget envelope** | **Partial, P/S.** Numeric bounds/day and unit caps, bounded retries and Restate reservation logic have tests; new approval action binds budget parameters. | No actual provider overage stop or cumulative day ledger proof. Budget raise route is unavailable; durable authenticated execution remains unconnected. |
| **US-10 Destructive approval/stop** | **Partial, P/S.** Credential-class gate, policy/shim denials and action-bound approval component exist. Unsupported mutations/stop fail rather than report success. | No mandatory interception of all generated actions, active destructive-operation authorization or independent watchdog. No human kill-switch completion proof. |
| **US-11 Human promotion** | **Partial, P/V/S.** Gate logic passes; evaluator cannot mark a Git merge merely from verification; exact-SHA bare promotion helper works in fixture; approval action binds repo/ref/base/candidate/evidence. | No connected authenticated approval→durable consume→exact Git mutation path; no `verification.yaml` evaluation or first-promotion state. Production deployment is out of scope. Later automatic drift criterion conflicts with controlling consensus and must be reconciled. |
| **US-12 Brokered credentials** | **Partial types/logic, P/S.** `CredentialGrant` carries work package, scope and expiry; privileged kind requires approval; approval action includes credential parameters. | No issuing/revoking broker, actual short-lived token, scoped fork key or model-context exclusion integration. Issuance route unavailable. |
| **US-13 Isolated worktree** | **Missing worker lifecycle; partial evaluator proof V.** Evaluator exports fresh commit snapshots in restricted scratch directories. | No worker disposable worktree creation/GC/claim lifecycle, separate UID or permitted-egress deployment. Evaluator snapshot is not a worker worktree. |
| **US-14 Goose headless** | **Partial, P.** Supervisor drains bounded output, reaps process group, handles timeout and validates structured completion; malformed/zero-exit garbage fixtures fail. | `run_goose` deliberately refuses execution. Side-by-side digest-verified1.49.0 supports the flags, but pinned source proves completed can follow stream errors and hooks are not a mandatory masking boundary; real success receipt remains unresolved. |
| **US-15 Typed decomposition** | **Partial, P.** `pipeline::decompose` and driver produce/test a fixed scaffold→implement→test DAG. | No spec-driven module decomposition or typed per-module interface contracts; no isolated parallel builder execution. |
| **US-16 Exact receipt** | **Partial, P/V.** Typed receipt serialization and contradictory completion rejection; evaluator requires clean exact SHA; projection event IDs are stable. | Claim→stage→result relationship not enforced durably. Failed/crashed variants do not carry SHA/claim identity. Timeout records a current SHA but no reconciliation workflow is demonstrated. |
| **US-17 Command prevention** | **Partial, P.** Policy tests cover blocked binaries, chains/pipes, traversal/substitution/background escapes; shim test proves denied command is not executed. | Opt-in shim is not every Goose tool call; no mandatory interception or worker OS backstop. Parser is a restricted custom splitter, not general shell AST enforcement. |
| **US-18 Output masking** | **Partial, P.** Pattern tests and real shim stdout/stderr masking pass; benign output is unchanged; `Masked` exposes redaction kinds. | No live model-boundary integration. Shim uses `.text` and discards redaction metadata; no redaction audit event is emitted. Heuristics do not prove universal secret detection. |
| **US-19 Dependency dispatch** | **Partial, P.** Driver tests reject cycles and honor blockers; pipeline tests prevent invalid stage transitions and terminal dispatch. | Runtime dispatch disabled; no durable claims/leases/parallel delivery. Worker stream capture is bounded, but full receipt diff/summary contract is not comprehensively bounded. |
| **US-20 Structure/memory** | **Partial, P.** AST feature tests prove direct/scoped call edges and ownership; dependents/blast-radius pure queries pass; SQL read/store/recall helpers exist. | No persistent graph ingestion, Bifrost embedding generation or semantic recall integration. API uses fixed qualifier blast radius; symbol resolution is intentionally incomplete. |

## Integration scenario coverage

The filenames in `e2e-tests.md` are a proposed inventory, not completed tests. Actual integration suites are evaluator `exact_revision.rs`, execution `shim.rs`, and sfctl `cli.rs`; several route tests live inside control-plane `main.rs`. No `crates/worker` exists; the actual crate is `execution`.

| Scenario | Actual coverage and status | Missing proof |
|---|---|---|
| **INT-01 submit/idempotence** | **Partial P/S:** in-process lane/inspect route tests; CLI HTTP-error tests. | Repeat-submit idempotence is absent (new ULID each time); no real CLI intake test. |
| **INT-02 holdout denial** | **Missing.** | Actual generator credentials cannot read real holdout store; evaluator denial fixture is different scope. |
| **INT-03 triple-run gate** | **Partial P:** arithmetic helpers. | Exactly three executions, ephemeral deployment and feedback routing. |
| **INT-04 opaque feedback** | **Partial source:** formatting helper. | End-to-end scenario-body exclusion assertion. |
| **INT-05 Goose contract** | **Partial P:** JSON parsing, failure, timeout and subprocess fixtures. | Real installed Goose run, supported flags, valid cost and diff on completion. |
| **INT-06 isolated worktree** | **Missing worker test; V is evaluator-only.** | Worktree allocation, distinct UID, egress restrictions and no inherited host secrets for Goose. |
| **INT-07 receipt/reconcile** | **Partial P/V:** typed receipt, exact verifier SHA and stable projection IDs. | Claim/stage linkage and timeout/crash recovery against durable state. |
| **INT-08 budget stop** | **Partial P:** budget math, local gateway mock, retry limit. | Real gateway hard cutoff and human escalation; provider cost reconciliation. |
| **INT-09 promotion gate** | **Partial P/V/S:** gate logic, action-bound approval primitives, bare CAS promotion fixture. | Integrated gate+verification+human authority+mutation; reconcile obsolete drift bypass requirement. |
| **INT-10 credentials** | **Partial types/logic.** | Broker, TTL enforcement and absence from actual model context. |
| **INT-11 observability** | **Partial P/S:** task/pipeline read routes and CLI JSON behavior. | Every transition auditable, all active work included, worker/spend/SHA fields and restart persistence. |
| **INT-12 knowledge** | **Implemented local API source; P pure gate, S new route test.** | Current aggregate pass and binding knowledge evidence to eventual durable claim. |
| **INT-LOOP** | **Missing/blocked.** | Real intake→qualifier→spec/contracts→isolated Goose→private holdout/deterministic checks→human approval→exact merge. None of the component fixtures substitutes for it. |

## Phase 9 checklist reconciliation

| Task | Genuinely completed component | Why the whole checkbox remains open |
|---|---|---|
| **T1 scaffold/CI shape** | **Complete:** five-crate Cargo workspace, Git repository, lockfile and documented CI sequence exist. **Do not scaffold again.** | No blocker for T1: tech-guide.md explicitly scopes executable CI out of the MVP. INT-LOOP remains a separate local verification gate. |
| **T2 shared contracts** | Receipt/Claim/CredentialGrant Rust types and receipt serialization tests exist. | JSON schema/versioned contract validation not found; receipt claim/revision coverage incomplete for failure variants. |
| **T3 durable control plane** | Feature-gated workflow/budget objects and unregistered fenced claim/lease/retry/cooldown journal exist. | No complete durable cascade/queue/authenticated worker integration or live replay proof. |
| **T4 projection** | Migrations, event IDs and journal-coupled claim-event delivery exist. Real disposable-Postgres dedup/rollback/version/rebuild/corruption fixture passed; see `claim-outbox-2026-10-26.md`. | Claim journal remains unregistered; whole-pipeline projection, live Restate replay, quarantine repair and journal re-export after full DB loss remain unproved/incomplete. |
| **T5 qualifier** | Pure four-factor scoring, hard gates and lane-routing unit tests are implemented. | Required O3 executable/calibrated qualifier spec and grounded input extraction are not established; diagnostic inspection now includes factors. Treat algorithm subtask complete, not product qualification. |
| **T6 execution** | Subprocess supervision/strict parsing/masking helpers and negative tests pass. | Daemon claim subscription, verified Goose CLI, distinct UID isolation and worker worktree lifecycle missing/blocked. |
| **T7 evaluator** | Actual exact-commit Cargo verifier, restricted fixtures and arithmetic pre-filter helpers pass. | Holdout store/runner, distinct UID proof, SAST and full feedback loop missing. |
| **T8 gateway/broker** | Default-deny gateway and atomic reservation client logic pass mocks. | Mandatory worker route, actual Bifrost verification and scoped Git credential broker absent. |
| **T9 gates/brake** | Pure gates, separate-local-account transport and action-bound approval primitives exist. | Actual operator deployment, private durable adapter, consequential mutation wiring and independent watchdog incomplete. |
| **T10 CLI** | All named command parsers and HTTP clients exist; JSON/status failure behavior passes fixtures. | Deny URL lacks matching server route; approvals/budget/stop return unavailable. Socket/action-bound approval flow not yet wired. |

Current-tree tests/clippy/fmt/build passed. Hard gates remain: INT-LOOP; live durable exact-revision receipt/claim binding; actual budget overage cutoff; actual generator-to-holdout denial. The saved checks establish their component boundaries only.

## Prioritized fix guidance

1. Preserve fail-closed runtime gates until isolated worker, durable claims and authenticated operator mutation path actually connect. Do not turn unavailable into success to satisfy test counts.
2. Close remaining durable intake/idempotence, redaction audit metadata and deny-route behavior. Diagnostic factor inspection and complete active-task listing have been fixed; neither establishes durable runtime acceptance.
3. Establish durable runtime ownership before claiming observability, replay or approval completion. A standalone approval record is not evidence that Git/budget/credential execution occurred.
4. Add dedicated INT-02 and INT-LOOP only after real identity/holdout/gateway prerequisites are satisfied. Retain a separate marker for mock/fixture coverage.
5. Reconcile stale plans: O1 was already resolved to hosted open-weights APIs; the user has now selected separate local operator account plus action-bound approval (no MFA claim). Do not reopen those choices. Keep unresolved implementation/proof work explicit.

### Concurrent work noted after this snapshot

Root reconciled the final component source: four-factor inspection, complete active-task listing, invalid-risk refusal, approval identity checks, exact pre-filter cardinality and claim journal/outbox are implemented at the documented component boundary. Final current-tree Cargo logs supersede the earlier101-test snapshot. Whole-story runtime status remains partial/missing; component presence and fixtures do not close live claim/delivery/replay acceptance.
