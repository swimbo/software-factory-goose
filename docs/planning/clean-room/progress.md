# Progress

Session log, test results, error log.

## Session start
- **2026-10-13** — Planning a clean-room software factory on Goose, per `dark-software-factory-report.md`.
- Environment: `/Users/bo/code/software-factory-goose` greenfield (not a git repo).
- Planning artifacts live in `docs/planning/clean-room/` (user-directed path).

## Decisions (locked)
D1 Working MVP factory · D2 Rust · D3 Restate · D4 open-weights via gateway · D5 greenfield demo · D6 monorepo (clean-room subproject) · D7 git worktrees. User confirmed 2026-10-13.

## Phase status
- Phase 1 Requirements: **complete**
- Phase 2 Pain Point Research: **skipped** (user-provided research)
- Phase 3 Data Map: **complete**
- Phase 4 User Stories: **complete** (16 stories)
- Phase 5 Architecture: **complete** (5-persona debate → consensus R1–R12)
- Phase 6 Tech Guide: **complete** (debate folded in)
- Phase 7 UX (CLI): **complete** (partial)
- Phase 8 UI: **skipped** (non-visual)
- Phases 9–14: **in progress** — Phase 9 implementation started (code written; build blocked by sandbox crates.io).

## Implementation state (Phase 9, in progress)
Workspace scaffolded at `clean-room/` (5 crates). Code written:
- `crates/shared` — typed Receipt/Claim/CredentialGrant/QualifierDecision/etc. (+ tests)
- `crates/control-plane` — qualifier (pure, + tests), gates (pure, + tests), Axum HTTP API
- `crates/execution` — Goose headless runner (typed Receipt, kill -pgid)
- `crates/evaluator` — deterministic verifier + holdout 2-of-3/90% gate (+ tests)
- `crates/sfctl` — clap CLI (submit/inspect/status/approve/deny/budget/stop)

Not yet wired: Restate workflow (durability), Postgres outbox projection, gateway budget wiring, full-loop integration. `git init` blocked by sandbox (manual step).

## Errors
- **Sandbox blocks crates.io** (`index.crates.io:443` denied, strict allowlist — `allowed_domains` cannot widen). `cargo build`/`cargo test` cannot fetch deps in this session. Build must run outside the sandbox (see command below).

## Testing (Phase 9/11 — verification)
- **31 tests pass, `cargo clippy` clean (0 warnings).** Breakdown:
  - control-plane lib: 18 (qualifier 4, gates 5, gateway 3, state 6)
  - control-plane bin: 2 (HTTP integration — submit→dark-lane, inspect round-trip)
  - evaluator: 5 (holdout gate, secret-scan, deterministic verifier)
  - execution: 3 (turn-count parse, kill-pgid, receipt)
  - shared: 3 (receipt round-trip)
- Fixed during testing: `ExitStatus::signal()` import, clap `env` feature, sfctl partial-move, and a **qualifier logic bug** (missing knowledge now a hard gate; weights rebalanced so high blast-radius routes human).
- Refactored control-plane into lib + bin (eliminated dead-code warnings).

## Remaining (integration layer, needs live system)
- Restate workflow (`workflow.rs`) — **compiles** against the real SDK (verified `--features restate`). Corrected API: macros on impl block, contexts take `'_`, `HandlerResult`, `ctx.promise`/`resolve_promise`.
- Postgres outbox relay — `projection.rs` written (migrate + idempotent upserts), pool wired.
- Gateway client — `GatewayClient` written (chat + default-deny budget read).
- Full-loop wiring — control-plane serves Restate (:9080) + Axum (:8080); execution plane's `resolve_workflow` POSTs the receipt to the workflow's `complete`.

## To actually run the loop (needs live services)
- `restate-server` (Docker Compose), running Postgres, the operator's **Bifrost** gateway (external), and registering the workflow endpoint. The code is wired; standing up these services + a smoke run is the final runtime step.

## Decision — Bifrost gateway (2026-10-15)
Switched the model gateway from the LiteLLM default to **Bifrost** (operator runs it on their network). Code: `gateway.rs` now uses the `x-bf-vk` header for chat + the governance API for budget reads; config is `gateway/config.json` (JSON); `compose.yaml` drops the gateway container. Debate waived (externally constrained) — see `decisions/2026-10-15-gateway-bifrost.md`. Port map: Restate host `:8090`, Axum `:8081`, SDK `:9080`, Bifrost external `:8080`.

## Research delegations (all complete)
- Restate Rust SDK (restate-sdk 0.12.1, embedded log + RocksDB + S3, MSRV 1.90) ✓
- Goose (aaif-goose/goose v1.49.0, `goose run --no-session`, recipes YAML, engine:openai providers, no native worktree) ✓
- Gateway (LiteLLM Rust core / Bifrost; GLM-5/DeepSeek-V4/MiniMax M2.5 ~15–20× cheaper) ✓

## Debate (complete)
5 personas → moderator synthesis (12 contested, 7 HIGH) → 1 response round → consensus. Artifacts: `consensus-plan.md`, `debate-transcript.md`. architecture.md + tech-guide.md updated with `## Debate Outcomes`.

## Open items (for user)
- **O1 serving backend — NEEDS_HUMAN_DECISION** (hosted open-weights endpoints vs self-hosted GPUs).
- O2 gate sample size (cost-bounded MVP resolution).
- O3 qualifier spec (follow-on doc before Phase 9).
- O4 operator auth/MFA.
- O5 scenario authoring/coverage/drift.
- O6 supply-chain (generator as attacker).

## Improvements workstream (2026-10-15)
New planning effort: fold 4 best practices from the `code-machine` analysis into the factory as **R13–R16** (scope confirmed: all 4, clean-room only; R13 as both layers; R16 Rust-native, no Python).
- Artifacts: `improvements-plan.md` (new, the phase plan), `consensus-plan.md` (+R13–R16), `findings.md` (+code-machine analysis), `user-stories.md` (+US-17…US-20), `architecture.md` (+components 7–10), `tech-guide.md` (+deps), `data-map.md` (+entities 16–20).
- Decisions: R16 backend = **tree-sitter + pgvector on the existing Postgres** (recommended; reuses infra, no Python sidecar). R13 = shim + OS backstop.

## Errors
- *(none)*

## Restart audit — 2026-10-26

- User requested an audit to ensure resumption does not start at Phase 1.
- Read all phase plans, current source, Git history, and the newer `next-steps.md` handoff. Result: **resume late Phase 9**, not Phase 1 or fresh scaffolding. Existing R13–R16 code and pipeline/gate commits must be preserved.
- Current baseline: `cargo test --workspace --offline` passed **61 tests**, zero failures/ignored tests (default features only). This supersedes the earlier 31-test snapshot; no current clippy or live-loop result is claimed.
- Source inspection found incomplete independent verification, actual merge execution, and pre-model masking; handoff also records missing isolation/holdout execution and no live loop proof. Phase 9 therefore remains in progress despite the handoff's broad code-complete wording.
- Corrected the Phase 9 status and added a current restart note to `phased-plan.md`. Detailed evidence: `restart-audit-2026-10-26.md`. No application code or live services changed during this audit.

## Late Phase 9 continuation — 2026-10-26

- User authorized proceeding from late Phase 9 through the remaining gates. Preflight: applicable planning phases recorded complete/skipped; architecture and tech guide include debate outcomes; Phase 9 and CLI E2E plans exist. O1 is resolved in findings/consensus despite stale references elsewhere. Story review remains deferred to Delivery. O4 operator authentication needs a focused decision; user approved the three-reviewer debate.
- Verified physical environment: `ba-2.local`, Darwin, uid 501; Docker engine available. Process environment has no Bifrost URL/keys, database URL, Restate URL, or generator/evaluator UID configuration. Values of credentials were not read or printed. No live infrastructure was started.
- Parallel Phase 9 work: verifier/exact-revision promotion helper; worker subprocess/receipt/policy boundary; Restate/gateway/projection contracts. Root owns pipeline transitions, API false-success removal, CLI outcomes, and AST regression checks.
- Test-first failures reproduced: negative/nonfinite budget acceptance; blocked-task dispatch; results/completion before dispatch; false-success approval/stop/budget/credential endpoints; missing task inspection; AST parser returning no call edges; CLI treating HTTP 200 error payload as success. Fixes are being checked with targeted tests; final aggregate results will follow.
- Live worker mismatch: installed Goose rejects the planned `--no-session` and `--output-format json` flags. No inference was attempted. Worker now fails closed until protocol and isolation are proven. This is a remaining implementation gate, not a passing live-loop result.
- Runtime routes remain unavailable until authenticated durable claims exist; the in-memory diagnostic pipeline is not a substitute for the Restate authority. Credential issuance, promotion, budget raise, and watchdog stop must not claim success before their dependencies exist.

## Late Phase 9 continuation — 2026-10-26 (O4 resolved)

User authorization: continue from late Phase 9 through remaining implementation/verification gates; approved the three-reviewer operator-authentication debate; then selected **“Separate local operator account and action-bound approval channel; no MFA claim.”** This resolves O4 mechanism selection and does not assert deployed identity proof. Phase 1 was not restarted.

Implemented and reviewed components:
- Worker supervision now bounds both output pipes, cleans process groups, clears ambient environment and rejects malformed completion/cost; shim policy and masking occur before shim results return. Live Goose stays unavailable until mandatory coverage and isolation are proved.
- Evaluator now reads an exact clean committed revision, exports a restricted snapshot and executes actual Cargo check/test under Seatbelt. Fixture tests prove failures are failures, host read/write/network canaries are denied, and bare Git promotion is exact-SHA compare-and-swap. Separate holdout UID and full scenario runner remain missing.
- Gateway refuses malformed/wrong-key governance data and requires atomic Restate reservation before forwarding; invalid budget values fail closed. Provider enforcement and Goose routing remain unconnected.
- HTTP mutation stubs return explicit unavailable rather than false success; evaluation alone cannot report a merge. CLI errors produce nonzero exits. Diagnostics now retain qualifier factors and show running/dependency-blocked tasks; unknown revision is null. Missing AGENTS.md and invalid qualifier values force human routing.
- New action-bound approval primitives, unregistered Restate approval journal, and kernel-peer Unix transport implement the selected O4 component contract. Forged body identities, mismatched actions/revisions/evidence, expiry and replay fail. Root/duplicate runtime identity configurations now fail too. No MFA/human-presence claim.
- Unregistered ClaimLeaseJournal adds immutable base/repository binding, attempt/token/worker fences, bounded lease renewal, cooldowns and three-attempt cap. Constructor configuration is not per-request identity; private adapters are still required.
- Setup check/up/register are separate; failures propagate, existing containers are not recreated automatically, Postgres includes vector, Restate data volume and ports are corrected. No existing services were changed.
- Evaluator pre-filter now rejects non-three-run scenarios, per-scenario failure washed out by aggregate successes, and unsafe opaque-feedback IDs. The old aggregate fixture had a one-run scenario; replaced with valid 27/30 and26/30 cases preserving the intended threshold.

Test-first mutations: added negative tests, observed failures, then fixed implementation for invalid numeric risk, missing inspect factors, omitted active status tasks, invalid operator identities, evaluator cardinality/aggregate/feedback. No ignored/fixme tests were introduced. Initial compile/interface failures were corrected using the pinned SDK; Cargo lock waits resolved without killing unrelated processes.

Scoped results (not the final aggregate gate): control-plane default-feature61 library +6 route tests passed; approval8, approval-wrapper4, operator-transport6 and workflow-filter13 tests passed in their targeted runs; evaluator library9 passed after pre-filter fixes. Final whole-tree commands/logs will supersede these counts. The earlier `verification/2026-10-26-tests.log`101-test snapshot predates these additions.

Additional proof: disposable pgvector0.8.2/Postgres16 fixture passed migrations twice, qualifier/audit/receipt idempotence, ordered projection and synthetic1536-dimension recall. Container and anonymous volume were removed. Operator socket example passed13 diagnostic checks and removed its temporary directory. Neither fixture proves a live factory or Restate crash/replay.

New external-contract finding: installed Goose1.0.16 is incompatible with the planned flags. Digest-verified official1.49.0 side-by-side version/help succeeds, but pinned source shows JSON `completed` after error/cancellation and non-mandatory hooks. `decisions/2026-10-26-goose-tool-boundary.md` is prepared; required debate confirmation requested while independent projection work continues. Do not activate workers or silently choose a fork/adapter.

### Open errors and gates

- **Open:** true INT-LOOP, generator-to-holdout UID denial, mandatory real gateway cutoff, broker/watchdog, private authenticated adapters and replay-safe consequential execution. See `plan-gaps.md`; no accepted-risk waiver.
- **Open:** durable whole-pipeline authority and queue/outbox/rebuild integration; journal component tests do not establish actual recovery.
- **Open:** pinned Goose mandatory tool/output/termination boundary requires the prepared focused decision; no status-string success claim.
- **Resolved:** fake verification/merge/approval success, invalid numeric fail-open paths, CLI success on error, stale O1/O4 status, setup false success/ports/plain-Postgres mismatch.
- **Resolved scope correction:** T1 required CI shape only. Tech guide explicitly excludes CI implementation; no provider workflow is required to close T1.

Phases9–11 are not complete. Enterprise grade, delivery, full Phase13 review/user approval, Phase14 zero-gap closure and final Done-Means-Done have not passed. No final project completion is claimed.

## Phase 11 Results — local component checkpoint, 2026-10-26

Final commands completed 2026-10-27 UTC (2026-10-26 America/New_York) using rustc/cargo1.94.0 against the unchanged dependency lockfile:

| Command | Result | Evidence |
| --- | --- | --- |
| `cargo fmt --all -- --check` | exit0 | `verification/2026-10-26-fmt-final.log` |
| `cargo test --workspace --all-targets --all-features --locked --offline` | **135 passed,0 failed,0 ignored** | `verification/2026-10-26-tests-final.log` |
| `cargo test --workspace --doc --all-features --locked --offline` | exit0 (no doctests defined) | `verification/2026-10-26-doctests-final.log` |
| `cargo clippy --workspace --all-targets --all-features --locked --offline -- -D warnings` | exit0 | `verification/2026-10-26-clippy-final.log` |
| `cargo build --workspace --all-features --locked --offline` | exit0 | `verification/2026-10-26-build-final.log` |
| `bash tests/setup_test.sh` | fixtures passed, exit0 | `verification/2026-10-26-setup-final.log` |

One initial full-target Clippy failure found a single-element loop in approval test preparation. Replaced it with the identical direct record mutation, preserving assertions; full verification then reran successfully. The failed log is retained as `verification/2026-10-26-clippy-pre-repair.log`. No flakes were observed in these final runs; numerical coverage/mutation scores were not measured. Local toolchain1.94 success is not an explicit MSRV1.90 test.

T3/T4 bounded journal/outbox implementation now includes transactionally retained events, monotonic snapshots, old-version conflict rejection, terminal quarantine and retained-event rebuild. The final real-Postgres fixture passed14 checks including concurrency, rollback and deliberate corruption; see `verification/claim-outbox-2026-10-26.md`. All task-owned test containers/volumes were removed. Live Restate crash/replay, full database-loss journal re-export and quarantine repair remain open.

Test adequacy self-review and preliminary story/gap audit remain explicit about missing live scenarios. **Phase11 is not complete; INT-LOOP and live operating boundaries have not passed.** The gate-readiness report preserves the later enterprise/delivery/audit/sign-off requirements. Awaiting confirmation for the focused Goose tool-boundary debate; the earlier O4 answer remains resolved and is not being reopened.

Local checkpoint committed as `d5e4e94` on `codex/late-phase9-verification`. No push or deployment. The user's pre-existing root README and Phase1/planning-file edits remain outside the commit; continuation notes in phased-plan/progress are retained in the working tree. Source was unchanged after the final passing commands. Next dependent step: confirmed Goose tool-boundary debate, then implement the selected mandatory worker boundary and continue G-01..G-11 through the remaining gates.

## 2026-10-27 — Goose boundary debate and first offline canary

User approved three-reviewer debate. Research, evidence ledger, positions, response round and scoped consensus are in `decisions/2026-10-26-goose-tool-boundary/`. Consensus selects a falsification-first offline spike only; no final worker architecture or activation is approved by the result.

The digest-verified v1.49.0 fresh `--no-profile --no-session` canary executed a harmless project SessionStart hook despite no advertised tools. Baseline and explicitly disabled-plugin controls did not execute it; all three reached the local stub. External-network denial was independently checked. Full artifacts: `verification/2026-10-27-goose-hook-spike.md`, `.json`, and `goose_hook_spike.py`. The exact flags also produced a startup banner before JSON; quiet-mode behavior is not tested. This falsifies relying on no-profile alone; it does not establish other configurations unsafe or safe. Worker stays disabled. Remaining work: evaluate a protected configuration or narrowly scoped patch and execute the remaining masking, cancellation, accounting, descendant-command and live identity gates.

## 2026-10-27 — protected Goose and continued Phase 9

User authorized protected Goose testing or a narrowly justified patch and continuation through remaining gates. Protected launch/Seatbelt fixtures denied four configuration writes through a real Goose MCP tool, allowed a task write, and prevented the known task-directory hook from executing; controls passed. This proves only the tested configuration boundary, not universal tool interception or distinct-UID isolation. See `verification/2026-10-27-goose-protected-config-spike.md`. No patch or live worker activation was selected.

Nine recording-provider masking canaries demonstrated split-secret leakage with per-chunk masking and successful bounded reassembly before masking for tested success/error channels. Notification-to-model path remained unexercised. See `verification/2026-10-27-goose-mask-boundary-spike.md`. A production helper now buffers complete bounded text and fails closed on unsupported/incomplete/oversize/invalid input; a local factory tool boundary checks policy before execution and masks both output streams. Mandatory Goose integration remains unproved.

Implemented bounded, unregistered components: immutable idempotent Restate intake; first-attempt fenced worker queue with no auto-reassignment; revision/manifest-bound prefilter and real restricted local holdout fixture runner; explicit branch-ref Git promotion plus action/evidence eligibility revalidation. Conservative gateway reservations use trusted, explicit reviewed model limits and integer microdollars, with mode fencing against mixing legacy counters. Provider pricing, actual quota enforcement and live gateway routing remain unverified. The duplicate governance-key ambiguity now fails closed.

Latest combined local gate: `cargo test --workspace --all-targets --all-features --locked --offline` **200 passed,0 failed,0 ignored**; fmt, doctests, all-target Clippy with warnings denied and all-feature build all exit0. Saved `verification/2026-10-27-*-latest.log`. Focused evidence: `2026-10-27-durable-intake.md`, `2026-10-27-worker-queue.md`, `2026-10-27-holdout-fixture-runner.md`, `2026-10-27-promotion-eligibility.md`, `2026-10-27-conservative-budget.md`.

Phase9 remains open: authenticate private adapters, provision and prove separate identities, enforce all tool paths and descendant command policy, connect durable queue/worker/outbox, protect actual holdout store, implement independent brake/broker and provider budget enforcement, then run true INT-LOOP. Later enterprise, delivery, full gap audit, zero-gap and final signoff gates are not passed. No deployed readiness is inferred from fixture tests.

Local continuation checkpoint committed as `83b9271` on `codex/late-phase9-verification`; user-preexisting Phase1/planned-progress and root README edits remain outside the commit. No push/deployment. Resume at runtime integration and open gates above; this is not a Phase9 completion entry.

## 2026-10-27 — continuation from 83b9271

Located installed native Restate 1.8.0 via local Node wrapper. Built `control-plane/examples/restate_replay_fixture.rs` and ran `python3 clean-room/tests/fixtures/restate_replay.py` in disposable temporary Restate and PostgreSQL17.9/pgvector0.8.2 instances using random loopback ports. Actual journal/SQL behavior passed: duplicate scheduling; first claim and duplicate pull; exact completion retry and forged lease rejection; three claim projection events; ten concurrent 100,000-microdollar reservations with seven successes; mixed legacy/integer budget denial; action mismatch and replay denial; budget/approval/queue/completion persistence across graceful restart and SIGKILL after acknowledgement. A second pull deliberately discarded its response after the first HTTP byte; the live claim was observed and the same request ID recovered the same single-attempt receipt across restarts. This is not proof of crash during an in-flight mutation or of deployed identities/private ingress. See `verification/2026-10-27-restate-replay.md`.

A real-server status request rejected JSON null (HTTP400 requires no body/content type), exposing a false mock assumption in the worker adapter. The backend and mock were corrected, with red/green adapter tests. Earlier closed-before-response attempt did not establish completed work and was not treated as recovery evidence.

Protected Goose-to-factory MCP fixture exercised six actual model-driven cases with local provider, including permitted command, blocked command, split-secret masking, invalid output and caller-authority refusal; real deployment/all-path coverage remains unproved. Cancellation fixture work exposed child-process cleanup issues and is in progress. Separate holdout owner reader and peer-authenticated transfer components passed their local tests; actual cross-UID deployment remains unproved. Worker adapter passes local tests and remains unregistered. Independent watchdog implementation is in progress; no existing users/services/credentials were changed.

### Continuation checkpoint — component gates and unresolved runtime boundaries

The offline all-target/all-feature workspace suite passed **288 tests, 0 failed, 0 ignored**; formatting, strict all-target Clippy, doctests, build, setup fixtures and seven Python MCP adapter tests passed. Logs are `verification/2026-10-27-*-continuation.log`. These tests do not establish the full factory loop or production identity boundaries.

Real disposable Restate/Postgres fixtures additionally exercised private adapter protocol, claim-history re-export and redacted projections, same-object approval races, and exact-ref promotion recovery. The protected holdout transfer, operator/worker adapters, independent stop router and family spawn broker remain unregistered components. Promotion's permanent per-ref fence deliberately quarantines subsequent mutations until a verified recovery mechanism exists. Restoring old projections requires a separate explicit cleanup; prior stored sensitive fields were not automatically purged.

Pinned Goose restricted-mode patch and broker process-group/initialization controls are undergoing final canaries. Same-UID fixtures do not prove separate-account containment. A reviewed OS mechanism is still needed to spawn and signal distinct-UID processes, contain escaped descendants, and recover after supervisor failure; no accounts, privileged helper, service, or credentials were provisioned. `plan-gaps.md` was reconciled, but full Phase 13 review remains pending. T2's versioned contract and receipt/attempt/claim linkage also remain open. Phase 9 and the INT-LOOP, enterprise and final gates remain incomplete.

Final restricted Goose candidate canaries subsequently passed: 14 entry guards, six terminal cases, six real MCP boundary cases, an ordinary interactive control, and the broker lifecycle's four cases plus ordinary process-group control. The prior candidate's initialization refusal falsely returned success; the patched candidate returns nonzero before any provider call. The lifecycle fixture stopped five observed processes in three groups and repeated the stop safely. Evidence: `verification/2026-10-27-goose-mcp-group-inheritance.md` and `verification/2026-10-27-goose-broker-lifecycle.md`. This uses a synthetic fixed command catalogue and same UID; it does not establish deployed isolation or full runtime integration.

The new `decisions/2026-10-27-os-supervision-boundary.md` prepares the unresolved OS authority decision for the required focused review; no approach has been selected or provisioned.

Local checkpoint committed as `d6d5652` on `codex/late-phase9-verification`. Pre-existing root README and Phase 1/phased-plan/progress changes remain unstaged. No push or deployment. Patch files retain unified-diff context whitespace; `git diff --check` otherwise passes excluding patch and raw log artifacts. The initial Goose investigation also caused a partial rustup 1.96.1 component/cache download; the process was stopped, the default toolchain was unchanged, and the partial files were left in place rather than deleting unverified shared state.

## 2026-10-27 — OS-supervision review and independent intake verification

User approved the three-reviewer OS-supervision debate. macOS security, Rust operations and contrarian recovery reviewers researched primary sources. Their shared evidence is **insufficient for a production decision**: neither a privileged native helper nor a dedicated VM has proved complete-family containment, independent stop through owner failure, and safe recovery. The debate skill's insufficient-evidence rule stops the recommendation path; `decisions/2026-10-27-os-supervision-boundary/evidence-ledger.md` and `spike-plan.md` record the options and concrete tests. No account, service, VM or privileged helper was provisioned. A local owned-child `setsid` canary demonstrated survival after killing the former group, then directly killed and reaped its child. `kern.hv_support=1` and local Swift availability do not establish VM entitlement, guest image or recovery. No qemu, limactl, tart or guest image was found in the checked workspace/PATH.

The disposable native Restate/Postgres fixture now exercises ten concurrent identical intake submissions, conflicting first-submission race (exactly one winner), conflict reuse, and retained records through graceful and SIGKILL restarts after acknowledgement; all pass along with existing fixture checks. This does not prove public authentication or an in-flight crash. See `verification/2026-10-27-intake-and-group-escape.md` and the runtime log. The fixture example passed strict Clippy, formatting and Python syntax checks. Phase 9 remains open; activation and INT-LOOP are not passed.

Additional independent work: the unregistered Unix intake router now checks kernel peer UID, fixed principal and bounded typed requests; four socket tests cover retry/conflict, spoofing, foreign records and refusal. Its narrow real backend recovered a committed record after a deliberately discarded response against disposable Restate; a dropped socket-peer fixture defect was fixed and its failed log retained. This is not cross-UID deployment or a guarantee that trusted backend and journal principal configuration match. An admin-SQL fixture discovered two synthetic initialized claim objects after Restate restart and used those keys to rebuild their SQL histories after disposable database loss; no production-complete inventory is claimed. See `verification/2026-10-27-intake-and-group-escape.md` and `verification/2026-10-27-claim-admin-discovery.md`.

Generated draft-07 snapshots describe legacy shared Receipt/Claim/CredentialGrant shapes only; snapshot drift and 13 independent schema/serde examples passed. They do not provide the planned receipt-to-claim/attempt/stage linkage or enforce a production contract. AST blast-radius lookup now includes all ambiguous caller files and excludes non-dependency edges; revision-scoped indexing and model recall remain open. The gateway client no longer inherits environment proxies: a synthetic pre-fix proxy intercepted one request, whereas the fixed client and credential/redirect controls passed; see `verification/2026-10-27-gateway-proxy.md`. No real provider or credentials were used.

Latest combined local suite: **298 passed, 0 failed, 0 ignored**; all-target strict Clippy, formatting, doctests and build passed (`verification/2026-10-27-*-os-final.log`). These are component gates, not Phase 9 or INT-LOOP completion. A VM feasibility inventory found no task-owned guest image or VM runner; owner-SIGKILL testing remains blocked on a proven independent observation and cleanup authority. No VM, account, service, or privileged helper was started or installed.

Local checkpoint committed as `c43194f` on `codex/late-phase9-verification`. The pre-existing root README, Phase 1 and phased-plan changes, and continuation notes in progress remain unstaged. No push or deployment.

## 2026-10-27 — containment spike and continued integration

User authorized the containment spike and continued implementation. An ad-hoc signed, task-owned temporary Virtualization configuration validated on the local macOS host, without starting a VM. No authenticated task-owned guest image or independently verifiable owner-death cleanup authority was established. The native blocked-spawn canary showed the brake does not return while child setup holds the family registry lock; after release the directly owned group was stopped and reaped. Existing `setsid` canary had already demonstrated group escape. These are negative controls, not containment approval. See `verification/2026-10-27-virtualization-prerequisites.md` and `verification/2026-10-27-blocked-spawn-canary.md`.

Implemented fail-closed prerequisites: claim renewal/completion require consistent stage and attempt; worker adapter rejects contradictory completion stages; diagnostic qualifier decisions no longer enter the unlabeled persistent read model; gateway binds its governance identity and reservation endpoint/unit to trusted client configuration and bounds response accumulation. Gateway decimal headroom now preserves governance numeric text and rounds maximum down and usage up to whole microdollars. An attempted workspace-wide `arbitrary_precision` feature broke tagged Receipt deserialization; the failed run is retained, and response-specific raw-token parsing restored the receipt contract. Holdout execution retains ownership until group cleanup before reaping, honors cancellation/deadline before queued spawn, and returns incomplete on the first unavailable run so later scenarios do not start while cleanup may be pending. In-flight cancellation still relies on asynchronous owned cleanup; escaped descendants and supervisor death remain open. See the corresponding verification records.

Latest all-target/all-feature locked offline workspace suite: **313 passed, 0 failed, 1 ignored**. The ignored database-dependent test was explicitly run and passed against a fresh disposable PostgreSQL cluster. Strict Clippy, formatting, doctests and build passed. Rebuilt disposable Restate/PostgreSQL fixtures passed journal, worker/intake adapter, approval, promotion, budget replay, claim-key discovery and re-export checks. A Clippy test-read issue was fixed and its pre-fix log retained. Results in `verification/2026-10-27-*-spike-*.log`; they do not establish live Bifrost, full Goose routing, separate identities, complete task authority, INT-LOOP or production containment. Previously persisted ambiguous diagnostic rows and legacy sensitive projections still need explicitly reviewed migration.

Local checkpoint committed as `31dd293` on `codex/late-phase9-verification`. The pre-existing root README, Phase 1 and phased-plan edits, and continuation notes in progress remain unstaged. No push or deployment.

## 2026-10-27 — continuation from 31dd293

The watchdog now reserves pending launches without holding the family lock across spawn. Stop closes admission, stops already registered groups, reports pending launches as unresolved, and cleans/rejects late children. Family locks isolate unrelated stops, the HTTP brake bounds concurrent work, and failed signals retain the unreaped ownership handle for revalidated retry; poisoned-lock and saturation cases remain fail-closed. The actual patched Goose broker fixture passed again, including the hung three-group case. These changes do not kill a still-blocked spawn, contain escaped descendants, or recover after watchdog SIGKILL. See `verification/2026-10-27-watchdog-pending-spawn.md`, `2026-10-27-watchdog-family-isolation.md`, and `2026-10-27-watchdog-failed-signal.md`.

Other local work: gateway credential-bearing URLs reject unsafe schemes and ambiguous components; worker durable-call keys reject ambiguous URL segments; the diagnostic pipeline refuses human-lane dispatch and evaluation without its build; evaluating claim projections require a matching current attempt and candidate; an unscoped diagnostic AST route is unavailable pending caller/repository/revision authority. The partial shell policy rejects ambiguous executable syntax; its initial safe-stderr regression was repaired and the failed full-suite log preserved. Holdout transfer waits for request EOF, and an unregistered evaluator selection fixture binds report task, revision, manifest digest and generation without claiming authenticated provenance or atomic revalidation. sfctl rejects path/redirect/proxy ambiguity and bounds response bytes. Existing IDs or data affected by stricter validation may require migration.

A restricted pinned-Goose fixture exercised six tool-policy cases through a synthetic loopback proxy: 12 calls had 12 prior synthetic reservations, and direct provider access was denied by the fixture sandbox. This is a narrow Python prototype, not the Rust gateway, real Bifrost, durable accounting, production ingress, or general streaming. See `verification/2026-10-27-goose-gateway-protocol-spike.md`. A separate handoff audit found no grounded qualifier producer or durable authority binding intake to task DAG and queue; do not connect provisional diagnostics as authorization.

Latest all-target/all-feature locked offline suite: **342 passed, 0 failed, 1 ignored**; the ignored database-dependent test passed separately in a disposable PostgreSQL fixture. Formatting, strict Clippy, doctests, build, real pinned-Goose broker and synthetic gateway fixtures, and disposable Restate/PostgreSQL replay/re-export tests passed. Logs use the `2026-10-27-*-resume3-final` suffix. These are component/fixture gates, not the live INT-LOOP, distinct-account containment, external Bifrost or completion. Production activation remains disabled.

Local checkpoint committed as `b499fa8` on `codex/late-phase9-verification`. The pre-existing root README, Phase 1/phased-plan edits, and continuation notes in progress remain unstaged. No push or deployment.

## 2026-10-27 — continuation from b499fa8

Queue schedule and queue binding now reject URL-ambiguous transport keys before accepting new work; the real disposable Restate replay exercised each invalid task key as well as its existing retry/restart cases. Previously persisted incompatible identifiers may require migration. An approval issue that succeeds durably but returns an invalid response now preserves the generated nonce for authenticated status reconciliation. Both are bounded changes, not deployed authority proofs. See `verification/2026-10-27-queue-key-alignment.md` and `verification/2026-10-27-operator-issue-reconciliation.md`.

A same-UID disposable watchdog root now receives an exclusive synced unresolved-run marker before listener creation or work; a restart after owner SIGKILL refuses the same root. A separate surviving guardian detected controller EOF and stopped and reaped its directly owned benign child. Neither experiment proves containment of escaped descendants, guardian loss, independent VM teardown, separate-account authority, or safe reconciliation/clearing of the latch. See `verification/2026-10-27-watchdog-recovery-latch.md` and `verification/2026-10-27-watchdog-controller-loss.md`.

An unregistered Rust validator recognizes only the two tested synthetic Goose request shapes, and a test-only mock fixture checks reservation-before-provider ordering. Neither establishes raw request authentication, cross-call provenance, SSE transport, a durable budget, or live Goose/Bifrost routing. See `verification/2026-10-27-goose-rust-protocol-boundary.md` and `verification/2026-10-27-goose-rust-reservation-fixture.md`.

Locked offline workspace all-target/all-feature tests passed **356, 0 failed, 1 ignored**. The ignored database-dependent diagnostic test passed separately against disposable PostgreSQL. Formatting, strict Clippy, doctests and workspace build passed (`verification/2026-10-27-*-resume4.log`). Disposable Restate replay and claim-projection recovery and the pinned Goose broker lifecycle fixture passed separately. These are component gates only: G-01 through G-11, production containment, connected INT-LOOP, later assessments and final sign-off remain open. Production worker activation remains disabled. No VM, existing service, account, credentials or deployment were changed.

Local checkpoint committed as `a0bed60` on `codex/late-phase9-verification`. Pre-existing root README and Phase 1/phased-plan edits and continuation notes in progress remain unstaged. No push or deployment.

## 2026-10-27 — continuation from a0bed60

The diagnostic driver now refuses dispatch or completion for an invalid graph, including duplicate task IDs, missing dependencies and cycles. Operator OS-identity lookup now bounds output draining as well as direct-child runtime, and rejects inherited automatic child reaping. The unregistered Goose protocol prototype rejects duplicate raw JSON keys, including nested encoded tool arguments, before the synthetic reservation path. These are not durable task authority, account provisioning or production Goose routing. See `verification/2026-10-27-driver-invalid-graph.md`, `2026-10-27-operator-identity-deadline.md`, and `2026-10-27-goose-rust-protocol-boundary.md`.

The existing Rust text-only gateway now passes a disposable integration with the actual Restate BudgetCounter: exhaustion denies before provider, provider failure retains reservation, and exhaustion survives graceful and SIGKILL restarts. A dropped acknowledgement after a committed reservation triggers no provider request; an explicit retry reserves again, so reconciliation remains open. Synthetic prices/provider responses are not live Bifrost or Goose tool proof. See `verification/2026-10-27-gateway-real-restate-fixture.md`.

The controller-loss fixture distinguishes actual EOF from leaked writers or unexpected data. A separately owned live group leader spike avoided the observed zombie-leader `EPERM`, rejected an injected signal failure without losing ownership, and demonstrated that premature leader death can leave a descendant alive. It remains a same-UID disposable candidate, not integrated or complete containment. A separate execution supervisor prototype that propagated group signal failures broke five normal tests on macOS `EPERM`; it was reverted and the defect remains open. An existing cancellation test failed in the first full rerun; the old log did not show marker timing. The test now uses descendant-ready/release synchronization and a positive control; focused tests and the subsequent full run passed, but the historical cause is not established. See `verification/2026-10-27-live-group-leader-spike.md`, `2026-10-27-execution-group-signal-failure.md`, and `2026-10-27-execution-signal-test-handshake.md`.

All-target/all-feature locked offline workspace verification passed **362, 0 failed, 1 ignored**; the ignored database test passed separately with disposable PostgreSQL. Formatting, strict Clippy, doctests, example build, disposable Restate replay including the real gateway budget fixture, and the live-leader spike passed (`verification/2026-10-27-*-resume6.log`). No production worker, account, service, VM or credential was changed. Phase 9, distinct-UID containment, real Goose/Bifrost routing, INT-LOOP and later gates remain open.

A separate unregistered idempotent budget object passed disposable Restate tests for dropped acknowledgement, same-ID concurrency, conflicting amount, denial replay and acknowledged restart. Its bounded history never evicts. The existing gateway still uses the old ledger and can double-reserve; adopting the new object requires trusted durable call IDs, exclusive migration/retirement of old authority and authenticated scope. Separately, a bounded live-leader output/status fixture passed timeout, oversized/truncated frame and injected signal-failure controls; it is not a production worker or escaped-process containment proof. See `verification/2026-10-27-idempotent-reservation-fixture.md` and `2026-10-27-live-leader-capture-spike.md`.

The subsequent combined locked offline run passed **365 tests, 0 failed, 1 ignored**, with the ignored database test passed separately on disposable PostgreSQL. Strict Clippy, formatting, doctests, example build, real disposable Restate replay and bounded capture spike passed (`verification/2026-10-27-*-resume7.log`). The prior failed full-suite cancellation log remains retained; no historical cause was asserted. Production and later implementation gates remain open.

An additional fresh-namespace, unregistered inference-authority prototype binds call ID, exact request and review digests, model, attempt and reservation amount in one journal state. Its one-way dispatch fence refuses a repeated begin after a discarded acknowledgement; disposable Restate tests passed concurrent begins, conflict and denial, lost acknowledgement, and acknowledged graceful/SIGKILL restart behavior. No provider was called, and a begin response is not a self-enforcing one-use capability. A trusted sole launcher, authenticated lease/request provenance, private ingress, exclusive existing-ledger migration, and in-flight crash proof remain open. See `verification/2026-10-27-inference-authority-fixture.md`.

Final combined locked offline verification passed **368, 0 failed, 1 ignored**; the ignored database-dependent test passed separately against disposable PostgreSQL. Formatting, strict all-target Clippy, doctests, example builds and expanded real disposable Restate replay passed (`verification/2026-10-27-*-resume8.log`). This is not Phase 9 or INT-LOOP completion; production activation remains disabled.

Local checkpoint committed as `8addd9d` on `codex/late-phase9-verification`. Pre-existing README and Phase 1/phased-plan edits and continuation notes in progress remain unstaged. No push or deployment.

## 2026-10-27 — continuation from 8addd9d

The actual execution shell creates a separate process group and survives a stopped outer live leader; a disposable delayed-marker fixture reproduced the escape with an unsignalled control and observed separate PGID. Wrapping the current execution binary therefore cannot establish containment. See `verification/2026-10-27-live-leader-execution-boundary.md`.

A trusted synthetic inference launcher connected disposable Restate inference authority to a loopback provider. Concurrent launches, dropped acknowledgements and killed launchers demonstrated no automatic duplicate provider call under the fixture's trust assumptions, including persisted fence state across restarts. The fixture cannot prevent direct provider bypass or reuse of a successful begin response; it is not production identity or containment. See `verification/2026-10-27-trusted-inference-launcher-fixture.md`. Focused fixtures and example Clippy passed; no new workspace-wide gate was run. Phase 9 and INT-LOOP remain open, production activation disabled.

## 2026-10-27 — continuation from 3de3692

A feature-gated inherited-group fixture for the real execution tool and owned live leader prevents the tested nested-shell escape, with no-stop and separate-group escape controls and masked stdout/stderr checks. The parent check is not authentication; setsid escape, owner death, safe output release, independent broker and distinct UID remain unproved. The fixture feature must not be treated as a deployment security boundary. See `verification/2026-10-27-live-leader-execution-boundary.md`.

A synthetic fixed-catalog inference gate hid begin results and passed concurrent, changed-body, forged-request and lost-response controls against disposable Restate. A sandboxed caller was denied direct access to the tested provider and Restate sockets. The same-UID gate lacks peer authentication, caller/task admission and protected credentials; it is not the actual Goose/Bifrost path. See `verification/2026-10-27-inference-gate-egress-fixture.md`.

All-target/all-feature locked offline workspace verification passed **369, 0 failed, 1 ignored**; the ignored database test passed separately against disposable PostgreSQL. Formatting, strict Clippy, doctests, example builds, disposable Restate replay, and the real execution/leader comparison passed (`verification/2026-10-27-*-resume9.log`). Phase 9 and INT-LOOP remain open; production activation is disabled.

Local checkpoint committed as `d8b7232` on `codex/late-phase9-verification`; pre-existing planning edits and README remain unstaged. No push or deployment.

## Continuation from d8b7232

Trusted-release fixture withholds actual inherited-group tool output until owned leader stop/reap and observed group absence. Focused controls and strict example Clippy passed. Peer-authenticated Unix catalog fixture passed identity and request controls but reproduced late revocation after status read allowing dispatch. A fresh unregistered same-object atomic admission experiment then passed three focused tests, strict all-target Clippy and full disposable Restate replay twice, including concurrent revocation, lost acknowledgement and restart. Revocation-first denies begin; admitted-before-revocation sends remain possible. These do not migrate existing authorities, establish deployed identity, contain escaped descendants or recover after guardian loss. No new workspace-wide suite was run; Phase 9 and production activation remain held. Evidence: verification/2026-10-27-trusted-release-fixture.md, 2026-10-27-peer-catalog-gate-fixture.md, 2026-10-27-atomic-claim-inference-fixture.md.

## Continuation from 85ea2c6

Reusable fixture-gated watchdog guarded release now drives the actual inherited-group execution example and refuses bytes until checked signal/reap/observed absence. A failed combined positive test was corrected to use a true single-process control; absence and EPERM refusal rules remain unchanged and historical cause remains uncertain. The peer-authenticated fixture launcher now uses same-object atomic admission rather than a cross-object status check. Forgery, concurrency, lost response and revocation ordering passed disposable journal checks. Wrong-peer early-close handling requires independently recorded kernel UID rejection; authorized transport remains strict.

Workspace all-feature/all-target tests passed **377, 0 failed, 1 ignored**, with the database-dependent test passed separately. Strict Clippy and example build passed. Initial replay hit a wrong-peer transport race; corrected full replay and focused transport tests passed. No new doctest gate was run. Production identity, authority migration, escaped descendants, guardian loss, protected credentials and actual Goose/Bifrost INT-LOOP remain open. Evidence: verification/2026-10-27-reusable-guarded-release.md, 2026-10-27-guarded-release-absence.md and 2026-10-27-atomic-peer-launcher-fixture.md. No production activation.

## Continuation from 0b6d993

Guarded cleanup now distinguishes owned leader state from output-release eligibility: a dead leader's same-group descendant is stopped in a real regression test while its frame remains withheld; EPERM preserves unreaped ownership and is never success. A reusable latch-bound admission component reserves a fixed private root before spawn and refuses same-root reuse after failure or owner loss. Alternate roots, same-UID tampering and surviving escaped work remain uncontained.

An unregistered Rust peer gate now connects kernel peer UID, immutable task/call catalog, private UnixRestateBackend atomic admission and a gate-owned provider operation. Public policy requires distinct non-root identities; real disposable integration still uses a same-UID fixture. The unregistered atomic begin response now returns JSON true; old in-flight fixture migration is unproved. Existing authorities were not migrated. Evidence: verification/2026-10-27-guarded-release-dead-leader.md, 2026-10-27-guarded-admission-latch.md and 2026-10-27-rust-atomic-peer-gate.md.

Combined all-target/all-feature locked offline suite passed **386, 0 failed, 2 ignored**; both runtime-dependent tests passed explicitly via disposable replay/database fixtures. Strict Clippy, example build and expanded Restate replay passed (verification/2026-10-27-*-resume12.log). No new doctest gate was run. Production identity, executable sealing, alternate-root exclusion, escaped descendants, guardian loss, existing-ledger migration, protected provider credentials and actual Goose/Bifrost INT-LOOP remain open; activation disabled.

## Continuation from 09da78b

Rust atomic peer policy now refuses catalogs spanning tasks or lease generations. Kernel peer authentication precedes body parsing, with a real Unix incomplete-body wrong-peer regression producing prompt 403 and no provider call. Guarded admission snapshots bounded no-follow executable content/metadata and cwd identity and rejects tested pre-spawn replacements. Recovery latch rejects ACL-bearing roots; macOS adversarial ACL test passed, Linux branch remains untested. These are mutation checks, not an atomic executable seal; same-UID after-check races, ancestors and alternate roots remain open.

Combined locked offline all-target/all-feature suite passed **391, 0 failed, 2 ignored**, with both runtime-dependent tests explicitly passed through disposable fixtures. Strict Clippy, example builds and expanded Restate replay passed (verification/2026-10-27-*-resume13.log). Production identity, trusted catalog provenance, authority migration, protected credentials, escaped descendants, guardian-loss recovery and actual Goose/Bifrost INT-LOOP remain open. Production activation remains disabled. No new doctest gate was run.

## Continuation from 94ef46f

A fixture guardian now owns the latch-bound guarded launcher and monitors controller EOF while awaiting output. It acknowledges controller-loss cleanup only after owned-group stop and observed absence. Focused EOF, invalid input, deadline, preclosed controller and signal-failure controls passed. Guardian death, leaked pipe writers, final liveness-check race, escaped sessions and same-UID tampering remain unresolved. Evidence: verification/2026-10-27-guarded-owner-controller-loss.md.

The reusable Rust gate now connects to a fixed loopback HTTP provider with gate-owned synthetic credential, exact model/payload/destination binding, generic transport errors, no proxy/redirect/retry and no second budget reservation. Real disposable Restate integration verifies one actual HTTP send under concurrent calls and refusal of forged/replayed/revoked requests. This does not establish production credentials, catalog provenance, Goose/Bifrost routing or exclusive existing-ledger migration.

Combined locked offline workspace all-target/all-feature tests passed **395, 0 failed, 2 ignored**, both runtime-dependent tests passed explicitly against disposable services, strict Clippy and builds passed (verification/2026-10-27-*-resume14.log). No new doctest gate was run. Phase 9, INT-LOOP and production containment/authorization remain incomplete; activation disabled.

## Continuation from cc31eac

The Rust gate now validates immutable provider binding before atomic admission and rechecks before send, preventing configuration mismatches from burning a call. Authenticated request work is bounded to eight slots with a two-second body-extraction deadline; admitted journal/provider operations are not canceled by a whole-handler timeout. Real Unix replay verified mismatch leaves no admission, overflow returns 429, incomplete bodies expire 408, and a subsequent valid request succeeds. Listener header/connection caps remain outside this router.

Read-only inventory found a running OrbStack cgroup-v2 Docker engine. A pinned already-local image, nonroot networkless/read-only task-owned two-lane spike showed setsid work surviving guardian death, a no-kill delayed marker, and externally requested Docker kill followed by stopped engine state and no late marker. Only uniquely labelled task-owned containers were removed. This does not establish cgroup emptiness or automatic independent owner-loss cleanup. Evidence: verification/2026-10-27-independent-containment-candidates.md and 2026-10-27-docker-owned-escape-spike.md.

Combined locked offline workspace tests passed **396, 0 failed, 2 ignored**; both runtime-dependent tests explicitly passed against disposable services. Strict Clippy, builds and Restate replay passed (verification/2026-10-27-*-resume15.log). Production identity/credentials, trusted catalog provenance, exclusive authority migration, automatic independent containment and actual Goose/Bifrost INT-LOOP remain open; activation disabled. No new doctest gate was run.

## Continuation from 1a2a2ea

A reusable fixture host guardian now creates and retains the full ID of its uniquely labelled disposable container, closes admission on controller EOF/deadline, and checks exact ID/label before kill/removal. Tests passed actual controller SIGKILL after escaped child survived its inner guardian, engine absence, repeat cleanup, wrong-ID/label refusal and failed-kill unresolved ownership. No task containers remain. Host guardian death, engine failure, pipe leakage and independent cgroup-empty proof remain open. Evidence: verification/2026-10-27-docker-owner-loss-guardian.md.

The Rust gate now has an experimental HTTP/1 Unix listener with accept-time kernel UID checks, fixed connection cap, 8-KiB/2-second header bounds, no keep-alive and lifetime-held connection permits. Real disposable replay passed silent/partial-header saturation, overflow, disconnect/response release, in-flight provider retention and valid dispatch. Protected socket provisioning, cleanup and graceful shutdown remain caller prerequisites. Hyper dependencies use already-locked versions.

Combined locked offline all-target/all-feature tests passed **396, 0 failed, 2 ignored**, both runtime-dependent tests passed explicitly, strict Clippy/builds and real disposable replay passed (verification/2026-10-27-*-resume16.log). No new doctest gate was run. Production identity/credentials, trusted catalog provenance, exclusive migration, independent automatic containment and Goose/Bifrost INT-LOOP remain open; activation disabled.

## User deployment clarification

Deployment target is the local NUC, not Railway. Architecture and next-steps now record the NUC as the target; existing activation gates remain required and existing host workloads must be preserved.

## NUC continuation from 98ab260

User specified local NUC rather than Railway and authorized environment verification while preserving existing services/data. Verified hermes-control -> nuc-hermes Debian13.6 x86_64 kernel6.12.107 systemd257 cgroupv2, Docker systemd driver, Rust1.98.1 in ~/.cargo/bin. Hermes dashboard/gateway/Docker remained active; existing failed user-unit history was preserved. Root disk is heavily used; task builds were isolated on /tmp, then target/cache/dev packages removed after logs were saved. Source/harness/logs and copied Restate binary remain in the documented owned /tmp directory (~239MiB).

NUC Rust gate: 11 worker adapter tests, seven gate tests and separately invoked real native Restate gate passed, plus strict Clippy. Added fail-closed Linux ext4 access/default ACL inspection after reproducing blanket non-macOS refusal. Kernel Unix UID, ACL mutation, symlink/socket replacement, saturated connection, forged/replayed/revoked calls passed. Mac focused worker/gate and Clippy portability checks passed. No new entire-workspace/doctest gate was run. Evidence: verification/2026-10-27-nuc-rust-gate.md and associated raw logs.

Containment: the first simple transient-unit empty-cgroup observation was not repeatable (ENODEV). Persistent delegated subtree passed repeated populated0 cleanup but a same-UID child escaped into its sibling. Using Docker's existing privilege boundary, two runs of a task-owned container/slice proof and two automatic host-controller-loss guardian runs observed populated0 on the same persistent worker-slice inode while anchor remained alive. Actual worker was nonroot/cap-drop/no-new-privileges, had no mounts/network, and visible cgroup membership write was denied. This does not rule out every escape, host guardian/daemon loss or host-restart ambiguity. Both test containers were removed; two empty task-created root-owned slices remain because exact scoped stop was denied (interactive authentication required). Exact names/cleanup status: verification/2026-10-27-nuc-docker-slice-spike.md. No unrelated service/account/container/data was changed. Existing guardian regression passed.

Protected distinct-identity supervisor provisioning remains an inert reviewed-prerequisite proposal, not installed. User is unsure of administrative access; sudo -n is unavailable. Production identity/credentials/catalog provenance, exclusive authority migration, authenticated independent brake, host-guardian/daemon recovery and actual Goose/Bifrost INT-LOOP remain open. Production activation remains disabled.

## NUC continuation from 488bf32 — 2026-10-28

The real NUC Rust/Restate gate now has a cross-UID fixture using public Policy::new: service/host UID1000 is denied, container UID1002 denied, pinned networkless cap-dropped read-only container UID1001 admitted exactly once; forged task/payload and replay denied. Only the service socket is mounted read-only through a protected host parent. NUC focused gate tests (7), real journal test and strict Clippy passed; exact logs/harness: verification/2026-10-28-nuc-cross-uid-gate/. Same-UID control/process access is not production provisioning, protected catalog provenance or real Goose/Bifrost integration.

Systemd transient-user-unit ExecStopPost now drives independent fixture cleanup after guardian SIGKILL. The full-ID/token/label/slice-inode manifest is durable before start; three NUC runs observed owned-container removal and same persistent worker slice populated0. A durable pre-create intent additionally reconciles only an exact expected container in Docker created state after a crash before full-ID manifest commit; two final injected NUC runs plus normal regression passed. Non-force removal rejects a concurrent start; malformed/wrong/running/ambiguous identity remains fail-closed. Six intent/ordering controls and guardian failure/retry controls passed. No task containers/user units remain; two previously documented empty root slices remain active because scoped stop needs authentication. Evidence: verification/2026-10-28-nuc-systemd-docker-recovery.md and 2026-10-28-nuc-systemd-precommit-intent.md.

Existing Hermes dashboard/gateway/Docker remain active; root/tmp availability stable and only confirmed task-owned build artifacts removed. Shared-source Mac workspace all-feature/all-target run passed **397, 0 failed, 2 ignored**; the real gate ignored test was explicitly exercised on NUC; the separate database-dependent ignored test was not rerun in this batch. Strict workspace Clippy and doctests passed. Production catalog/credential provisioning, exclusive old-authority migration, authenticated independent brake, manager/daemon/host-restart recovery and actual Goose/Bifrost INT-LOOP remain open; activation disabled.

## NUC continuation from c8e0c68 — 2026-10-28

User clarified that model and reasoning must be selected by the existing Bifrost complexity router, not hard-coded. Read-only inspection found normal auto rules scoped to the desktop key and no matching local pricing rows; desktop credential value was neither read nor reused. Concrete factory-only provisioning proposal and public official Ollama price evidence are recorded, but API/schema, task credential issuance, exact route/fallback/output-reasoning contract and mandatory budget enforcement remain open. Existing Bifrost/router configuration was not changed and no live inference was sent.

Built exact pinned patched Goose1.49 source on NUC. Default Linux candidate retains refusal-before-provider for restricted stdio MCP; separate explicitly fixture-feature candidate passes six actual Goose→stdio MCP→Rust execution controls and bad-init zero-provider control. In-flight real Goose/MCP plus setsid descendant cleanup passed twice through independent systemd ExecStopPost and the existing persistent slice populated0 observation. Provenance/logs: verification/2026-10-28-nuc-goose-linux.md. Feature remains fixture-only; helper upstream unit test blocked by missing offline env-lock. Removed only owned build/cache/sysroot/debs; retained ~1.3GiB Goose candidates/source/logs plus earlier239MiB assets in documented /tmp directory. No task processes/containers remain; existing services active.

Authenticated Rust brake middleware now has a trusted StopAuthority seam; Registry behavior/policy unchanged. NUC actual UID1003/wrong-key/unknown-target controls were denied; authorized UID1002 stopped the exact owned Docker target and same slice observed empty. Pending/verified/unknown state and bounded cleanup permit retry reconciliation without duplicate stop. This stop path requires no journal/gateway, but fixture key/identity provisioning and durable brake-state recovery are not production-ready. Evidence: verification/2026-10-28-nuc-authenticated-brake.md and docker-brake-reconciliation.md.

An unregistered fresh-namespace genesis inventory fixture passes five state tests but does not establish cluster freshness, prevent rebootstrap after total state loss, close old handlers or bind production task membership. No authority migration marked complete. Shared-source all-target/all-feature locked offline workspace tests passed **405,0 failed,2 ignored**, strict workspace Clippy and doctests passed. The database-dependent ignored test was not rerun in this batch; earlier NUC real-journal tests remain scoped evidence. Production provisioning, exclusive authority, budget contract, real Bifrost INT-LOOP, enterprise/artifact audit and final acceptance remain open; activation disabled.

## Factory key and conversation continuation — 2026-10-28

User provided factory key name software-factory-goose-int-loop-c085b7e and NUC file reference /home/bo/.hermes/bifrost/factory-secrets/software-factory-goose/credential. Verified 0600 uid1000 regular single-link file and private task parent. Constant-time NUC memory-only comparison confirmed exact named key match; no credential/hash printed or persisted in repository. Read-only metadata confirms three dedicated auto complexity rules, no configured fallbacks, Ollama-only provider scope; no expiry or key/provider budget found. No key/router write or live inference occurred. Scoped update proposal is not executable until deployed management API/access compatibility is verified.

New unregistered two-turn conversation fixture binds exact initial request/lease, route-snapshot cost maximum, one reserved begin per turn, trusted exchange and exact continuation; revocation/replay fail closed. Review fixed arbitrary route substitution before admission. Actual patched Goose six-case bridge initially failed because of tool argument serialization whitespace; normalized provider-derived fixture arguments resolved it. Full disposable replay passed on macOS with candidate SHA512bc701...586fb, 12 synthetic calls/12 reservations; three Rust tests, formatting and strict all-target control-plane Clippy passed. Raw log saved verification/2026-10-28-conversation-replay.log. This is not a NUC/live Bifrost INT-LOOP or authenticated transcript provisioning. No new entire workspace suite was run. Live exact route token/price bounds, key lifecycle, production transcript authority and exclusive deployment remain open.

## Key-settings waiver and next integrations — 2026-10-28

User explicitly waived factory-key expiry and gateway-level budget settings; no key/router mutation performed. Existing task ledger remains assumed pending explicit monetary-scope clarification. Read-only live Bifrost inspection confirms direct9084 retains automatic complexity tiering but may make budget-counted semantic embedding and fallback LLM calls before routed answer; context relay9087 additionally supports document/image side calls. Published answer-model rates alone do not cover the classifier. Exact findings: verification/2026-10-28-factory-auto-route-contract.md. No live inference occurred.

Goose synthetic macOS bridge now derives durable fixture call IDs from trusted synthetic task/worker/lease/attempt/turn; full disposable replay passed and raw log saved. New service-owned tool relay refuses worker-supplied result fields, correlates exact pending arguments/ID, consumes once, captures actual sanitized execution reply outside worker identity and binds it into real disposable Restate on NUC. Kernel UID1000/1002 denied, UID1001 accepted once, forged continuation/replay refused. Three focused tests and NUC actual journal integration passed. Existing Stapled factory containers were discovered during read-only inventory and preserved; no Goose registration or migration used their Restate state. Isolated target/cache removed, source/logs retained as documented. Evidence: verification/2026-10-28-nuc-tool-relay-journal.md.

Actual Goose→cross-UID relay integration, durable relay restart fencing, supervisor integration, live auto-router accounting and production acceptance remain open. No new workspace-wide Rust suite was run for these fixture changes; prior405 snapshot remains historical. Key expiry/gateway budget are not prerequisites after the user waiver; activation remains disabled for the other runtime gaps.

## INT-LOOP cost-cap override — 2026-10-28

User explicitly authorized: no monetary cap for this INT-LOOP, including the original $0.75 task ledger. This supersedes the prior pending budget-scope question for this run only. Do not alter Bifrost key expiry/budget or desktop/shared router configuration; use the factory key securely and existing auto complexity selection. Replay fences, task identity, credential isolation, approval/promotion, output and process bounds remain required. Production monetary defaults outside this named run are not waived. Existing NUC services, Stapled deployment and data must be preserved.

## Late Phase 9 — real uncapped Goose generation/evaluation, 2026-10-28

Continued from 1ad8838 without restarting Phase 1. User explicitly waived every monetary cap for this named INT-LOOP, including the $0.75 task ledger; no Bifrost key/router settings were changed. Actual NUC generation10 completed Goose → UID-gated host relay → existing Bifrost model:auto → fixed structured two-file writer → exact continuation. Both routed observations were deepseek-v4.1-flash:1017, selected by the existing router. Its durable fence is done, manager recovery verified, both owned roots removed, exact worker slice empty, original inert create guard intact and Docker/Hermes services active.

Candidate b468844bcfb6a3ec4e337efe8e2e6d45cdedbd90 (baseline40b84df26736e522e0e98180d836b24e021d788b) passed 21/21 independent isolated executions and candidate tests; evaluated/committed blobs match. A second exact-blob run passed21/21 after enforcing the >=90% aggregate gate. The accepted ref remains absent; proposed promotion is prepared, not approved/executed. Evidence: verification/2026-10-28-real-int-loop/ and verification/2026-10-28-runtime-verification.md.

Errors/mutations: earlier distinct attempts remain fenced and retained, never reset. Fixes include held-open nc stdin, strict complete HTTP framing, coherent bounded response sizes/incremental parsing, observed bounded Bifrost reasoning_details/SSE comments, and exact Goose per-delta reasoning reconstruction in the continuation. Retained response diagnostics were reparsed offline before fresh attempts. A reference evaluator exposed its Python PATH assumption; fixed absolute contained interpreter and then reference/actual runs passed. Independent audit found missing all-runs aggregate enforcement; collector/finalizer and negative controls fixed, actual exact blobs revalidated. Full chronology: verification/2026-10-28-live-intloop-attempt.md. Provider captures remain sensitive host-only0600/0700 data; literal credential-byte checks are not general sanitization.

## Phase 11 Results — current component evidence, 2026-10-28

Locked/offline all-target/all-feature Rust workspace:408 passed,0failed,2ignored; both runtime-dependent cases subsequently exercised through the full disposable native Restate/Postgres replay and diagnostic projection. Formatting, strict workspace Clippy, doctests and all examples build passed. Final Python discovery:111 passed,0failed. Raw logs: verification/2026-10-28-uncapped-*.log and final-evaluator-controls.log. No UI exists; UI design/accessibility gate is not applicable. These results do not certify complete P0 acceptance, test adequacy/mutation coverage or enterprise readiness.

## Current blocking boundary and gate reconciliation — 2026-10-28

Independent story, runtime/architecture and NUC deployment reviews reconcile current gaps in verification/2026-10-28-late-phase9-boundary-audit.md. G-01–G-11 remain open; no full INT-LOOP or production activation claim. Diagnostic entrypoints, authoritative intake/cascade/queue/launcher/wall/promotion integration and separate operator provisioning remain incomplete. Docker live restore is disabled; Docker-only guardian/operator fixtures do not establish daemon-independent stop. Noninteractive sudo unavailable and no host account exists for fixture UID1002. No shared service/account/data was modified, restarted or migrated.

A human choice is pending on the explicit host-administration mechanism in deployment/nuc-administrative-boundary.md. Existing Docker fixture permission is not silently treated as approval to modify the host OS. No root installer ran. Existing pre-session dirty phase1/phased-plan/progress edits and root README are preserved outside these commits.

Canonical done-means-done checklists were located in bo-planner0.2.0/done-means-done. This is a blocking-state reconciliation, not the final all-phase audit:

| Phase | Gate | Status | Evidence |
| --- | --- | --- | --- |
| 9 | Scope fidelity / every P0 user story fulfilled | fail | independent boundary audit; G-01–G-11 |
| 9 | Architecture and supported production deployment | fail | diagnostic/fixture entrypoints; unprovisioned roles/independent supervisor |
| 9/11 | Build, lint, typed compilation and component tests | pass | uncapped workspace/replay/projection/examples/Python logs |
| 11 | Every P0 live acceptance / full connected E2E | missing | generation/evaluation slice passes; intake→merge loop remains incomplete |
| 11.6 | Enterprise A/B assessment | missing | profile/must-pass selection and assessment not reached |
| 12 | All earlier phases closed / explicit delivery sign-off | missing | no delivery approval requested or inferred |
| 13 | Full artifact coverage and user-approved gap severities | missing | current audit preliminary; no user certification |
| 14 | Zero open blocker/major gaps and final sign-off | fail | G-01–G-11 retained, no waiver |

Continue from late Phase9 operating boundaries, preserving every unknown attempt and the scoped candidate. Do not regenerate the successful candidate or replay a prior fence merely to resume.

## Authorized NUC administration — 2026-10-29

User: "Authorize the scoped NUC host administration using the existing Docker permission. Continue from a33c9db through production integration and verification until finished. Preserve existing services and data." This resolves the previously pending administrative mechanism; no repeat permission request is needed for necessary scoped installation/owned canaries. Shared restart/reboot, new human login keys and action-bound promotion remain outside this authorization. Reconfirmed current kernel/engine/daemon identity and existing active services; previous worker slice empty. Root-bridge and frozen-late-start observations are recorded in the new dated canary evidence. Identity PLAN/APPLY tool and private runtime intake/queue entrypoint are in implementation/review, not deployed or certified. Continue late Phase9, notPhase1.

## Phase 11A added — 2026-10-30

User requires Harness Efficiency and Reliability before Phase 12 delivery. See phase-11a-plan.md. Implementation is candidate-only: existing fixed relay authority is preserved. Report figures are unverified inputs. Baseline/evaluation evidence, production integration and the >=20-task/three-run paired gate remain required; no activation or performance improvement is claimed. Concurrent root-finalization work is excluded from this milestone.

### Phase 11A candidate implementation checkpoint — 2026-10-30

Added disabled candidate modules under execution/harness: contained QuickJS host,
brokered tool calls/read batches, stable versioned profiles and optional schemas,
complete Rust output normalization, private attempt artifacts, stall intervention,
metadata-only observations, frozen 20-task public suite and fail-closed paired gate.
Request-path audit: verification/2026-10-30-harness-request-audit.md.

The general capability is not registered in the fixed protected relay or launcher.
Real pinned-Goose/general relay integration, bounded production broker transport
proof and 120 independently accepted/billed model runs remain required. Phase 11A
is incomplete and blocks Delivery; no savings or activation is claimed. Concurrent
root-finalization files remain outside this milestone.

Scoped Phase 11A verification: 19 real-runtime/component Python tests, 63 execution
Rust tests, seven existing MCP adapter tests, strict execution Clippy and Ruff pass.
Native Linux ARM64 host smoke controls passed; AMD64 Rosetta refuses unsupported
close_range before eval. Evidence and remaining admission blockers:
verification/2026-10-30-harness-candidate.md. Formal code review is in progress.

Phase 11A review completed with eight validated findings, all fixed inline. Final
candidate suite: **28 passed**, including finite heap-cap controls; a cap-disabled
isolated mutation build is rejected by the new test. Final native Linux ARM64
host passed five controls including broker IPC. Review/fix evidence and explicit
remaining phase prerequisites are in verification/2026-10-30-harness-candidate.md.

## Late Phase 9 continuation — Root finalization, 2026-10-30

The user-approved three-reviewer finalization debate reached consensus; its
contract and exact Root-authorization amendment are folded into the decisions
index and tech guide. Same-key immutable finalization preserves the launch fence,
unknown spend and separate human approval. The native Root/UID2000/UID2001
authorization canary passed, including publisher death after authorization-file
fsync and before parent fsync: the retained pending marker denies admission.
Receipt: `/tmp/sfactory-identity-admin-0iadbv5i` on the NUC. This is a synthetic
permission/crash proof, not production journal acceptance.

Current local scoped verification: 16 Root-finalization Rust tests and 33 Root
deployment Python tests passed. Earlier disposable journal receipts predate the
mandatory authorization check; a new real-UID2000 fixture is required. No later
phase is closed by these component results.

Evaluator canary2 completed 21/21 independent holdout executions plus candidate
tests with exact-ID cleanup. Canary3's owner-loss signal was denied by the
administrative transport; no kill or owner-loss success is claimed. Its independent
deadline closed and froze the exact empty cgroup. Separately reviewed cleanup
removed only the recorded exited container and stopped only the fixture broker;
the result remains unknown and all records/cgroup are retained. Production
candidate binding and owner-loss acceptance remain open.

SDK5 preparation uses a distinct 9085 endpoint and fresh r3 identifiers, retaining
SDK4 and prior histories. Installation, attestation, registry transition/replay,
real Goose/Bifrost integration, evaluator provenance and finalization remain
separate gates. Preserve existing NUC services and data; resume late Phase9.

### Subsequent native acceptance and source publication

The updated isolated journal fixture subsequently passed with actual PID1-managed
UID2000, cap-empty/NNP and mandatory Root authorization: unpublished direct403,
exact authorized concurrent/lost-response replay, changed-payload403, permanent
worker fence, sanitized status, projection deletion/reexport, persistent conflict
quarantine, and owned SDK/Restate restart with unchanged history digests. Its
owned processes/data were cleaned up; synthetic Root records remain retained.
See verification/2026-10-30-authorized-journal-fixture.md for the initial failed
credential check, separately reviewed recovery, receipt chain and trust limits.

Canary4 then supplied linked actual broker SIGKILL/independent deadline/replay
refusal and exact-ID cleanup observations. The original native driver response
remains unknown, with its post-kill failure stage unavailable; the later Root
observations do not rewrite it. All records and frozen target cgroup remain.

Current complete local workspace verification passed 505 Rust tests, zero failed,
two ignored across 50 suites, formatting and strict all-target/all-feature Clippy.
Deployment discovery passed 262 tests after the separate per-generation evaluator
drafts. Logs: `/tmp/sfactory-workspace-20261030-finalization-current.log`,
`/tmp/sfactory-clippy-20261030-current.log`, and
`/tmp/sfactory-deployment-20261030-runtime-final.log`. These component receipts do
not close full P0 acceptance, mutation adequacy, enterprise assessment or Delivery.

Verified source milestones are committed and pushed in separate commits through
`fb724fc`; publication is not runtime activation. SDK5 remains inactive. User
approved a new three-reviewer admin-ingress/old-SDK retirement debate after the
direct admin bypass was identified. That debate and its bounded disposable proof
must precede the real registry transition and connected INT-LOOP.

### Unix-admin debate and failed-probe reconciliation

The approved three-reviewer ingress debate reached conditional consensus for a
Unix-only admin endpoint, fixed trusted UID2004 operations and permanent old-SDK
retirement. The disposable pinned-runtime permission proof passed; the v4 toy SDK
also passed native startup and inherited-descriptor denial. Its combined fixture
then registered only the old toy SDK and failed on the first direct discovery:
the probe used HTTP/1.1 against the SDK's HTTP/2-only server. Read-only snapshots
showed no invocations, queue entries or counter effects; independent native HTTP/2
discovery succeeded. Exact owned-fixture shutdown passed with data retained and
the original unknown outcome preserved. See
verification/2026-10-30-unix-admin-sdk-fixture.md. The corrected client still needs
native connection reuse/closure controls and the full retirement/recovery fixture.

The inactive production finalizer package is installed and its fixed unknown
evidence passed native Root capability-empty/NNP readiness, without publishing
authorization or calling the journal. SDK5's separate process probe is installed
but unrun; SDK5 remains inactive. No production registry transition, new real
claim, connected INT-LOOP, promotion or later-phase completion is claimed.

### Late Phase 9 — protected ingress and recoverability checkpoint

The approved three-reviewer ingress debate reached conditional consensus. The retained synthetic HTTP/2 fixture subsequently completed old-SDK retirement, connection denial, cached-output recovery and exact owned shutdown; its initial 9082 registration remains unknown and was not retried. The separate 9086 continuation succeeded with data retained. See `verification/2026-10-30-h2-retained-recovery.md`. This does not establish production admission.

SDK5 inherited-descriptor enforcement passed native positive and connected-extra-FD negative controls. A production-only guarded binary was installed inactive, with the old binary preserved; see `verification/2026-10-30-sdk5-inherited-fd-guard.md`. Expanded restore-history probe v2 was installed create-only and remains unexecuted. A separate native streaming check verified the 248 MB pinned Restate executable without exceeding the restricted bridge memory limit.

The recovery preflight caught an incorrect mode assumption before any production mutation: the real Restate base is UID/GID2004 mode0755 beneath its protected mode0700 journal parent. Validation now binds those exact modes; existing permissions were not changed. Production SDK retirement, offline backup/restore, Unix-admin cutover, SDK5 registration, admission publication and the connected real INT-LOOP remain pending. The transition marker must remain until prospective admission is independently published and revalidated; the finisher now enforces that ordering.

The first isolated discovery attempt failed at its positive probe and discarded the error output. A distinct diagnostic attempt retained bounded Root-owned output before also failing; neither has a success receipt and neither changed production. Original attempts and records are retained. Later verification phases remain open.

The distinct discovery diagnostic subsequently passed with explicit `stdin=DEVNULL`. Native FD0 metadata explained the earlier failure without relaxing the probe: inherited stdin had a different filesystem inode despite the same device number. Diagnostic3 passed actual HTTP/2 discovery, connected-extra-FD denial and exact synthetic shutdown. Runtime activation now binds that distinct success and the FD0 observation, preserving both failed attempts. See `verification/2026-10-30-sdk5-discovery-native.md`. Current deployment verification: 419 tests passed in `/tmp/sfactory-deployment-20261030-transition-current2.log`. Per-stage Root bridge bindings and recovery readiness still precede production retirement.

### Phase 11A protected runtime and runner checkpoint — 2026-10-30

Protected spending ingress, incremental lease-bound attempts, the resumable 120-attempt driver and independent public-task acceptance are implemented. An isolated native Linux fixture verifies kernel UID roles, private journal transport, persistent caps and restart behavior. Actual pinned Goose completed both variants through the same spending journal and bounded independent evaluator in a synthetic rehearsal; no rehearsal counts toward the live benchmark. See verification/2026-10-30-harness-runtime-runner.md and verification/2026-10-30-harness-linux-private-runtime.md.

Live runs remain 0/120. The approved $5 UTC-day/$0.75 permanent-task ceilings remain binding. Production transition/launch binding, enforceable all-path charge bounds and correlated provider-billed classifier/embedding/answer receipts remain prerequisites. No candidate activation, route change or delivery occurred. Phase 11A remains incomplete and required before Phase 12.

### Phase 11A audited usage metric and Linux transport — 2026-10-30

The user explicitly accepted audited usage-rated performance costs. The implementation now freezes a shared tariff/cost basis in runner configurations and attempt identities, retains exact Decimal provenance, rejects incomplete/mixed evidence, and keeps billed debits separately labeled. The same spending journal accepts tariff-bound usage audit evidence with no reservation refunds or cap resets; legacy billed scopes retain their wire digest and behavior. An actual Goose rated-journal rehearsal passed both independent acceptances. An isolated real Linux typed/QuickJS pair also passed, including kernel UID checks, in-flight cancellation and independent disposable cleanup. All are component/synthetic proofs, never 120 live attempts. See verification/2026-10-30-harness-usage-rated.md.

Verified 128 Python tests and 19 Rust runtime tests; strict Clippy, scoped Ruff and production-feature example compilation passed. Full source review completed with no unresolved findings. Live attempts remain 0/120 and candidate disabled. Complete physical-call capture, enforceable all-path bounds and production registry/generic-launch admission remain open. The $5 UTC-day/$0.75 permanent-task caps and all other safety/approval gates remain unchanged.

### Phase 11A physical-bound composition and admission preflight — 2026-10-31

Reviewed all-path charge composition now multiplies each provider contract by its physical-attempt bound, includes fallback alternatives, and emits the existing sole-owner RouteBound. It rejects missing coverage, invalid/expired maxima, overflow and manifest capacity; the affordability check preserves $0.75 across all six permanent-task attempts. The production library exposes the spending modules without registering or deploying an endpoint. Verification: 273 library tests passed, one existing disposable-fixture test ignored, and strict registry-sidecar Clippy passed. See verification/2026-10-31-harness-charge-preflight.md.

A fresh public provider review does not establish affordable enforced billable maxima for the existing route. Full-context-style reservations exceed the task cap; prompt bytes and requested output alone are not a supported billable envelope. Generic protected Linux launch and the production owner/registry integration also remain incomplete. Live attempts remain 0/120; candidate disabled, $5 UTC-day/$0.75 permanent-task caps and all existing gates retained. No paid inference or production state change occurred.

### Phase 11A gateway physical capture source checkpoint — 2026-10-31

Published isolated core1.11.2 derivative `28d60ee` in the Bifrost repository, with typed append-only physical records, final-wire owner permits, bounded JSON/SSE/NDJSON usage, exact framing witnesses and sticky unknown/replay refusal. Actual provider decoder and socket regressions pass: 26 new top-level race tests, full upstream schemas/utils short race regressions and eight-lens source review. Structural JSON aliases, unary read allocation and premature Content-Length/chunk trailer completion were reproduced red and fixed. See verification/2026-10-31-gateway-physical-capture.md.

This is source qualification, not a joined native gateway deployment, durable owner/usage-normalization binding or generic protected Linux launch admission. Affordable provider-backed billable maxima remain unsupported by the available evidence. Live attempts remain 0/120, performance gate unpassed, candidate disabled; $5 UTC-day/$0.75 permanent-task caps and existing evaluator/registry/approval gates are unchanged. No paid inference or production mutation occurred.

### Phase 11A owner/usage and generic Linux source integration — 2026-10-31

Implemented optional guarded production SDK owner registration, fixed-owner Unix frontend, authenticated physical usage normalization/audit clients and a generic Root-supervised Linux adapter. Fixed reviewed listener-creator/peer identity and directory-read incompatibilities without weakening custody checks. Actual returned-builder discovery now covers existing-service preservation. See verification/2026-10-31-owner-usage-linux-integration.md.

Verification: 153 harness tests passed (one skipped), 280 registry library tests passed (one existing fixture-dependent test ignored), strict Clippy/Ruff passed; native registry binaries compile and seven owner tests pass. Actual pinned Goose synthetic worker pair was independently accepted. Distinct-UID native client proof accepts self-bound readable service sockets and rejects Root-created/chowned listeners and search-only parents. These are component proofs only.

Live attempts remain 0/120, candidate disabled, performance gate unpassed. Provider-supported affordable all-path billable maxima remain absent; Cloud num_ctx and soft provider budgets do not supply them. Joined gateway permit/capture/audit custody, Root inventory/fence/catalog/current leases/cgroups and privileged supervisor/daemon-loss/cleanup qualification remain required. $5 UTC-day/$0.75 permanent-task caps, no refunds/unknown retries and existing approval/evaluator/registry gates are preserved. No paid inference or production state change occurred. Phase 11A remains incomplete and required before Phase 12.

### Phase 11A owner migration and native mount correction — 2026-10-31

Fixed the active owner migration to preserve historical unbound catalog bytes and select the unique active intent. Native qualification reproduced Docker/runc descriptor-bind rejection; Root-private hash-verified file snapshots and inode-pinned relay links now pass restricted worker reads, socket peer checks and actual execution. Review reproduced and fixed an intermediate execute-bit regression; known cleanup removes snapshots, unknown create retains them. See verification/2026-10-31-owner-migration-mounts.md.

Verification: 153 Python harness tests passed (one skipped), 281 registry library tests passed (one existing fixture-dependent test ignored), eight native owner tests and both native runtime binary checks passed; strict Clippy/Ruff, 19 focused Linux tests and the final native execute/mount component proof passed. No component proof is production launch admission or a paired benchmark result.

Provider recheck confirms actual OpenAI-compatible max_tokens support; full-context reservations are not the sole possible bound. Exact dated public Cloud metadata still provides no supported hosted input-count or rendering/tokenization expansion contract. This external evidence is required before paid inference; post-response usage does not supply pre-dispatch authority. Joined gateway acquisition/capture/audit and full privileged launch/watchdog/loss/cleanup qualification remain incomplete. Existing single-use aggregate begin can supply root acquisition without another money authority; no speculative handler was added. Live attempts remain 0/120, candidate disabled, $5 UTC-day/$0.75 permanent-task caps and all prior gates unchanged. Phase 11A and delivery remain blocked.

### Phase 11A custody and supervisor loss checkpoint — 2026-10-31

Published source fixes fence exact owned cgroups independently of Docker availability/resource drift, detect zombie owners, persist protected sanitized captures/audits, and bind gateway calls to one-use owner roots with inherited cancellation and a final HTTP admission guard. Nine native loss cases and protected SQLite restart/role proofs pass; 161 Python tests pass, four skip. Source review and discriminating guard/cancellation negative controls completed. See verification/2026-10-31-custody-loss-qualification.md for exact evidence and limits.

Live attempts remain 0/120; candidate disabled. Supported pre-dispatch provider input/output/fee bounds, joined real-wallet/private-ingress/bootstrap and full production start/service-group/daemon/host-loss qualification remain required. No paid benchmark inference or production activation occurred. $5 UTC-day/$0.75 permanent-task caps, no refunds/unknown inference retries and existing evaluator/registry/approval gates remain intact. Phase 11A remains incomplete and required before delivery.
