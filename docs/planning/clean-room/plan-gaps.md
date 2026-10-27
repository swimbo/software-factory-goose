# Plan Gaps — preliminary implementation register

Updated 2026-10-26 during late Phase 9. **This is not the completed Phase 13 audit or user-approved severity list.** It records actionable gaps found while implementing, so later phases cannot mistake local test success for delivery.

Severity: `blocker` = missing/broken in-scope core outcome; `major` = significant correctness/quality gap; `minor` = low-impact drift; `nit` = polish. No blocker is accepted or waived. Status `in_progress` does not imply a passing gate.

## Audit Scope

Audited against: `user-stories.md` (US-1 through US-20), `architecture.md` and `consensus-plan.md` (runtime/authority boundaries), `tech-guide.md` (versions/setup), `e2e-tests.md` (INT-01 through INT-12 and INT-LOOP), `phase-9-plan.md` and selected Phase 10–14 gates. Full per-artifact Phase 13 review remains pending. `ui-plan.md` is not applicable because no UI is in scope. UX flow walkthroughs and all earlier phase checklists have not yet been re-audited.

| Planning Artifact | Code Paths Audited |
| --- | --- |
| user-stories.md / e2e-tests.md | All five crates; detailed matrix in `verification/2026-10-26-story-coverage.md` |
| architecture.md / consensus-plan.md | control-plane main/workflow/projection/gateway/approval/transport, execution main, evaluator verification |
| tech-guide.md | Cargo manifests/lockfile, compose.yaml, setup.sh, installed Goose version |
| phase-9-plan.md | T1–T10 and every local hard gate |
| ux-plan.md / phase plans 1–8, 10–14 | Full audit pending; canonical later-phase gates inspected, not certified |

## Gaps

| ID | Source (artifact:section) | Expected / proposed fix | Actual / code evidence | Type | Severity | Owner Phase | Status |
| --- | --- | --- | --- | --- | --- | --- | --- |
| G-01 | consensus-plan.md:R3/R4/R5; phase-9-plan.md:T3/T4 | Restate-owned goal/task/lease/retry/cooldown state, authenticated queue, journal-derived projection and reconstruction | `main.rs::AppState` is diagnostic memory; unregistered `workflow.rs::ClaimLeaseJournal` adds fenced lease state; outbox work in progress. Connect durable cascade, identity and replay recovery before dispatch. | partial | blocker | 9 | in_progress |
| G-02 | user-stories.md:US-13/US-14/US-17/US-18; phase-9-plan.md:T6 | Durable worker subscription, disposable worktrees, distinct UID/OS isolation, real Goose protocol and mandatory policy/masking | `execution::run_goose` deliberately refuses activation; supervisor/shim fixtures are passing components. Installed Goose1.0.16 is incompatible with planned flags; pinned1.49.0 investigation in progress. Build mandatory tool boundary and queue/reconciliation before enabling. | partial | blocker | 9 | in_progress |
| G-03 | user-stories.md:US-6/US-7/US-8; consensus-plan.md:R1/R2/R11 | Private holdout store and runner; generator denial; deterministic verification plus opaque feedback | `evaluator::verify_worktree_evidence` runs actual Cargo/Seatbelt fixtures; pre-filter arithmetic is enforced. No deployed generator-to-holdout isolation or scenario runner. Implement and prove those boundaries. | partial | blocker | 9/10 | open |
| G-04 | user-stories.md:US-5/US-9/US-12; phase-9-plan.md:T8 | Mandatory Bifrost route, conservative per-call bound, cumulative unit/day ledger, scoped short-lived credential issuance/revocation | `gateway::chat` passes mock governance/reservation tests but Goose has no caller path. Broker absent; routes unavailable. Connect enforcement, exact pricing/token constraints and broker, then prove cutoff and TTL. | partial | blocker | 9 | open |
| G-05 | consensus-plan.md:O4; user-stories.md:US-10/US-11 | Separate operator UID, action/evidence-bound durable authorization and replay-safe mutation; independent brake | `approval.rs`, `approval_workflow.rs`, `operator_transport.rs` have scoped tests; journal is unregistered. No provisioned accounts, authenticated private Restate adapter, authoritative eligibility/execution coupling or independent watchdog. O4 mechanism is resolved, these are implementation/proof gaps. | partial | blocker | 9 | in_progress |
| G-06 | e2e-tests.md:INT-01..INT-12/INT-LOOP; phase-11-plan.md:Verification | Every P0 acceptance criterion demonstrated live; actual full loop | Existing tests are units, local HTTP/CLI/OS fixtures and disposable DB checks. Real Goose/Bifrost/holdout/approval/merge loop has never passed. Complete scenario specs and isolated runtime verification. | missing | blocker | 10/11 | open |
| G-07 | user-stories.md:US-1/US-2/US-4; phase-9-plan.md:T5/T10 | Immutable idempotent intake, grounded factor reasoning, auditable status and working gate CLI | `main.rs` now shows factors/all active tasks and rejects invalid risk values, but intake is not durable/idempotent, defaults are provisional, revision is explicitly unknown, deny path and privileged CLI flow incomplete. Finish through authoritative state rather than enlarging memory cache. | partial | blocker | 9 | open |
| G-08 | user-stories.md:US-15/US-16/US-19; phase-9-plan.md:T2/T3 | Typed spec/module interfaces; versioned cross-plane schema and full claim/receipt linkage | Fixed three-task DAG and Rust shared types exist; exact verifier SHA and lease fencing are tested separately. No spec-derived module contracts, complete failure-receipt linkage or schema validation. | partial | major | 9 | open |
| G-09 | user-stories.md:US-20; consensus-plan.md:R16 | Persisted AST ingestion and gateway embeddings/recall, used in qualification/execution | `memory.rs` parses direct/scoped call edges and has DB helpers; no indexing/embedding orchestration or qualifier integration. Synthetic vector recall is not model embedding proof. | partial | major | 9 | open |
| G-10 | architecture.md:Security; tech-guide.md:Setup | Reproducible supported runtime, private ingress, source/dependency provenance | Setup now fails on errors and preserves existing containers. Server image/version and authenticated ingress remain unselected/unverified; Goose pin is being checked. Credential TTL has no broker-policy maximum yet. Resolve before activation. | partial | major | 9/11 | open |
| G-11 | enterprise-implementation:11.6/12/13/14; canonical Done-Means-Done | Enterprise A/B gate, completed artifact audit, zero unresolved gaps and explicit delivery/final sign-off | Not reached. No grade, acceptance, override or final audit is claimed. After runtime gates pass, select assessment profile/must-pass categories and execute full prescribed gates. | missing | major | 11–14 | open |

## Out-of-Scope Deviations

No intentional scope expansion accepted. Okayr remains a proposed future integration. Executable CI is explicitly out of the MVP in `tech-guide.md`; a missing CI-provider workflow is **not** a gap. The existing documented CI shape satisfies that portion of T1.

## Accepted Decisions

O1 hosted open-weights through external Bifrost and O4 separate local operator/action-bound approval without MFA are resolved user decisions. They do not waive operating tests or accept any gap above as `wont_fix`.

## Verification

- [ ] Every planning artifact has been diffed against implementation.
- [ ] Every requirement/story/architectural decision has a fixed-or-gap row.
- [x] Preliminary gaps categorized by severity; each has a concrete source and implementation location.
- [x] Scope distinction recorded; no CI-provider or Okayr expansion inferred.
- [ ] User has reviewed and approved the complete gap list before Phase 14 certification.
