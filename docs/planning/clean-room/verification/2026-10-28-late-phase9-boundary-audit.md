# Late Phase 9 boundary audit

Three independent source/evidence reviews cover stories, architecture/runtime integration, and NUC deployment/recovery. This is a current implementation audit, not completed Phase 13 approval or an enterprise grade. No production story is accepted on the strength of a fixture.

## Story reconciliation

| Stories | Current result | Remaining operating boundary |
| --- | --- | --- |
| US-1–4 | Partial: intake, qualification, factors, projection components and disposable runtime tests | Authenticated immutable sfctl ingress, grounded repository factors, durable task cascade/queue and reconstructible audit/status; `control-plane/src/main.rs` remains diagnostic memory |
| US-5/9 | Partial: journal budget tests and real auto-routed experiment | Production single daily/task spend authority, exact route/classifier bounds, exclusive migration and mandatory launcher; this named experiment alone is uncapped |
| US-6–8 | Partial: immutable candidate passed isolated host-held scenarios | Protected production holdout authority, cross-UID store denial, durable result publication and connected opaque failure/retry loop |
| US-10/11 | Partial: action-bound approval and exact-Git fixtures | Separately provisioned operator and authenticated independent stop, actual human decision and production mutation/recovery channel |
| US-12 | Missing production broker | Task-scoped credential issuance/expiry/revocation and privileged grant flow; existing experiment key is not a credential broker |
| US-13/14 | Partial: actual restricted Linux Goose generated exact two-file candidate | Durable claim→mandatory launcher→fresh worktree→receipt lifecycle under provisioned production authority |
| US-15/19 | Partial: typed components and DAG/queue tests | Spec-derived module contracts, persisted dependency dispatch and isolated parallel builders |
| US-16 | Partial: evaluated and committed blobs match exact candidate | Complete durable claim/attempt/stage/SHA receipt with timeout/reconciliation, not only a local run fence |
| US-17/18 | Partial: policy, masking and restricted tool fixtures | Mandatory interception across every supported production launch/output path and redaction audit |
| US-20 | Partial: AST and dependency helpers | Repository/revision-scoped indexing, real semantic recall and qualifier integration |

The audit found an implementation defect: repetition votes were checked per scenario without the required 90% of **all runs** aggregate (consensus R2). The collector/finalizer now both enforce it and reject a 14/21 negative control. The actual candidate's original observation was 21/21, so that observation is not invalidated; exact committed blobs passed a separate 21/21 revalidation under the stricter gate. The reference canary also exposed reliance on PATH for Python: the execution adapter intentionally clears PATH to `/usr/bin:/bin`, while the pinned image's interpreter is invoked at fixed `/usr/local/bin/python3`. The corrected reference passed all 22 isolated challenges and cleanup.

## Production entrypoints

`control-plane/src/main.rs` binds only diagnostic WorkPackageWorkflow/BudgetCounter; private intake, worker, atomic-authority and operator adapters remain unregistered. Privileged routes return unavailable. `execution/src/main.rs::run_goose` still refuses production activation. The task-only Python live driver is not a substitute for that durable pipeline. The full INT-LOOP requires intent → qualifier → decomposition → Goose → wall → approved merge; the current successful generation/evaluation slice leaves it open.

## NUC administrative and recovery boundary

Read-only inspection reconfirmed Docker29.8.0/systemd cgroupv2 with live restore disabled, worker slice empty, and root-owned `cgroup.kill` mode0200. UIDs1001/1002 used by Docker fixtures have no corresponding host passwd accounts. `bo` UID1000 cannot use noninteractive sudo. A Docker-only guardian/operator cannot establish a Docker-independent brake. A root helper outside Docker and an independently usable separate operator require reviewed administrative provisioning. No existing unit/account/shared-service configuration was changed by the audit.

A conditional inert created-container name reservation is not daemon/host recovery. Retain its exact object and all ambiguous fences; never start/remove/rename it to make tests green. Production catalogue, late-launch closure, journal inventory/migration, private ingress, guardian/daemon/host recovery and protected boot reconciliation remain open.

## Next dependency order

1. Settle the administrative mechanism in `deployment/nuc-administrative-boundary.md`; review and implement the independently protected supervisor/operator boundary.
2. Connect immutable grounded intake, durable task/queue ownership, sole claim-bound launcher and one journal/gateway authority; preserve old state and shared services.
3. Connect authoritative isolated wall results and action-bound exact-revision promotion/brake. The prepared candidate promotion request is not approval.
4. Run complete INT-01–12/INT-LOOP, prescribed testing/adequacy, enterprise assessment with selected profile, full artifact audit and explicit delivery/final acceptance. No later phase is marked complete here.
