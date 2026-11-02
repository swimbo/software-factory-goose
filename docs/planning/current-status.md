# Current status

Updated: 2026-11-02 (America/New_York). **Active; resumed at the user's request.**

## Objective and gates

Finish Phase 11A: Harness Efficiency and Reliability, including the protected Goose integration and the actual 120-attempt paired benchmark. Phase 11A is incomplete and remains a Phase 12 delivery prerequisite.

- Live benchmark attempts: **0/120**. No paid benchmark inference has run.
- Candidate: **disabled**; no deployment, activation or promotion authorized by source publication.
- Preserve **$5 per UTC day** and **$0.75 per permanent task**, including all six paired attempts across repeats/days. No refunds, cap resets or inference retries after unknown acknowledgement.
- Retain Goose, the protected relay and Bifrost's existing auto route, exact frozen models, independent evaluator/holdout isolation, registry authority and approval gates.
- The user approved separately labeled audited usage-rated costs for the performance gate. Provider-confirmed billed debits remain distinct; missing metrics remain unknown.

## Completed and published

Factory branch: `codex/late-phase9-verification`. Source-composition checkpoint: `2b2588d`, pushed to upstream. Subsequent protocol verification is recorded below.

The resumed source checkpoint adds a broker-only, read-only wallet verification and a sequenced broker check of the current Root scope before each v2 physical dispatch. Factory commits `e0ff427` and `c5f32f5` and Bifrost commit `82c3a20` contain the core changes. A [fresh joined fixture](clean-room/verification/2026-11-01-physical-revalidation-join.md) verified the new path across the real wallet, Root scope RPC, broker, Bifrost handler and collector with synthetic provider and route inputs. The updated installer was reconstructed and replayed, and four synthetic native exchange and stream scenarios passed. A point-in-time check cannot prevent dispatch after subsequent authority loss, so gateway egress fencing and production failure cleanup still require qualification.

[Physical-call admission ordering](clean-room/verification/2026-11-01-physical-admission-ordering.md) now prevents concurrent calls from reaching the sequenced broker check out of order. A cancelled wait or queued call at capture sealing remains fail-closed. The full Go schema suite and native fixtures passed; provider inputs remain synthetic.

A [native owner-loss fixture](clean-room/verification/2026-11-01-gateway-peer-slice.md) also fenced a separate unprivileged gateway-like process and child already inside the worker's attempt slice. This is not a Bifrost launcher or production egress proof. One earlier failed fixture retains its frozen, empty slice without a synthetic owner-revocation receipt; a later guard-crash setup and an unattributed frozen slice remain preserved for reconciliation.

The [gateway peer check](clean-room/verification/2026-11-01-gateway-peer-process-check.md) requires a Root schema 3 configuration for live physical confirmation and checks the kernel-reported process against the attempt cgroup and reviewed executable. A subsequent [socket peer pidfd check](clean-room/verification/2026-11-01-gateway-peer-pidfd.md) pins the peer across each exchange. Isolated cross-UID testing established that Root's executable inspection needs `CAP_SYS_PTRACE` in that test environment; production capability scope and evaluator isolation remain unqualified. The real gateway launcher, joined live path and egress fencing remain open. The full configured Python harness most recently ran 258 tests with six skips.

Bifrost commit `9f7fc47` adds a source-only private listener lifecycle for a pre-bound Unix listener. It serves exchanges serially, stops admission on an unknown exchange, preserves the launcher-owned socket pathname and closes an active connection on cancellation. The gateway is poisoned when the listener exits; a stuck router or plugin still requires supervisor fencing and process/descendant cleanup. Five focused listener tests passed on the newer composed Linux source, including a race-enabled run in a network-disabled container. Bifrost commit `6538116` adds the pinned listener and tests to the source installer. The exact pinned preimage was reconstructed at `/home/bo/sfactory-gateway-listener-w97vqLY0/reconstructed` on `hermes-control`; an altered listener was refused before target writes, installation succeeded, replay was refused, and listener and protocol tests passed there under Go's race detector. Eight installer tests and Ruff also passed. The listener tests use synthetic connections; it is not connected to a production constructor or qualified with the real wallet and route. This source installation neither launches nor admits a gateway.

Bifrost `52e30a5` and the updated factory fixture [join the actual listener to the wallet rehearsal](clean-room/verification/2026-11-01-listener-wallet-join.md). The network-disabled run completed one synthetic provider call and settlement before the parent cancelled the listener. Root construction, route, authorizer and charge bounds remain synthetic; no production admission or paid attempt occurred.

Bifrost `c14651e` adds and tests [adoption of a supervisor-supplied listener descriptor](clean-room/verification/2026-11-01-gateway-inherited-listener.md), including an isolated cross-process `exec` handoff and a fresh synthetic wallet rehearsal. The actual Root launcher does not yet supply this descriptor, and pathname custody, production bootstrap and failure cleanup remain unqualified.

An isolated [listen-identity test](clean-room/verification/2026-11-01-gateway-listen-identity.md) showed that Root listening before handoff makes the broker observe UID 0. Bifrost `30a0f17` adds gateway-UID activation of an already-bound, non-listening socket; the actual Go activation passed a cross-UID test and a separate synthetic wallet rehearsal. The production Root launcher must bind and hand off the socket without listening and close its own copy. Socket-path custody and launch/cleanup qualification remain open.

The new [Root bound-socket primitive](clean-room/verification/2026-11-01-root-gateway-bound-socket.md) checks protected ext4 ancestry, creates the socket with the gateway/broker identity and records one-use intent under current-grant and guard checks. A distinct-UID ext4 fixture passed the actual broker path check and Go activation. Root schema 4 pins the helper; both harness profiles bind its source. The Root method is not yet wired to a gateway process launcher, and its guard integration has synthetic unit coverage only.

The [bind/cleanup fence](clean-room/verification/2026-11-01-gateway-bind-cleanup-fence.md) serializes schema 4 binding and cleanup across processes and fences execution before cleanup. [Absence reconciliation](clean-room/verification/2026-11-01-gateway-bind-absence.md) handles an intent when no handoff receipt or socket exists; [created-socket cleanup](clean-room/verification/2026-11-01-gateway-created-cleanup.md) also handles a matching, durably recorded inode before handoff. Ambiguous creation or any bound/handoff receipt remains unresolved. The exact socket-helper source is pinned to the cleanup pathname contract and loaded only for binding, so cleanup-only startup does not depend on that helper. Cleanup after gateway handoff or process launch remains unimplemented.

**Work in progress:** A source-only gateway pre-exec barrier and synthetic Linux fixture are now in the checkout. The helper checks identity, executable, socket, owner and cgroup information and waits for a release before executing a gateway; its source is included in both profile fingerprints. An earlier version passed a network-isolated cross-UID fixture including denial when its controller died before release. The final socket-type check passed its [native fixture replay](clean-room/verification/2026-11-02-gateway-exec-barrier.md), including a non-stream-socket rejection. The fixture did not test actual cgroup migration, and the helper is not connected to a Root launcher or production Bifrost bootstrap. Production route and credential custody, post-release owner loss and descendant cleanup remain unqualified. Resume by completing and testing that integration, not by enabling the candidate.

- Protected spending authority, one-use gateway acquisition, durable capture and independent settlement RPC have component and restart proofs. These do not establish the full production path.
- An [isolated joined fixture](clean-room/verification/2026-11-01-wallet-root-gateway-join.md) now exercises the durable wallet, real Root scope methods, protected broker, actual Bifrost handler, capture and collector together. Root construction, registry, route, provider, authorizer and bounds are synthetic; production admission remains unqualified.
- The same isolated chain now [tests task and daily reservation ceilings separately](clean-room/verification/2026-11-01-joined-cap.md) against the real journal, with synthetic opening balances and bounds. The hosted all-path charge envelope remains unproven.
- Actual Root prepare/start and PID1 guard pass supervisor-group loss, guard-main crash and current-lease expiry with a live supervisor. Exact owned resources were independently checked after cleanup. Registry/catalog/wallet replies in these native launch fixtures are explicitly synthetic.
- The real long Unix relay path and a Darwin child-exit race were reproduced and corrected.
- Latest full configured Python harness: **258 run, 252 passed, six skipped**. The joined guard outage tests use mocked system boundaries; see [combined-loss evidence](clean-room/verification/2026-11-01-guard-combined-loss.md).
- A fresh exact-pin composed Bifrost source stage now includes physical capture/owner-root, governance, routing, embeddings, normalization, transport identity and native HTTP admission. Its server package compiles on Linux with Go1.27.2. Four existing public-loopback test groups pass. The final source manifest contains 1,891 files. The truncated older archive and absent historical build-cache paths were not reused.

Evidence: [progress](clean-room/progress.md), [phase plan](clean-room/phase-11a-plan.md), [native lease expiry](clean-room/verification/2026-11-01-native-lease-expiry.md), [composed gateway source](clean-room/verification/2026-11-01-composed-gateway-source.md).

## Published protocol checkpoint and resumed verification

The Bifrost publication worktree is separate from this repository:

`/var/folders/3b/9571c77j0078bs3mpjrqcxj80000gn/T/sfactory-remaining-gateway-publication-04afte_6/integration`

Branch: `codex/remaining-source-audit-20261031`. Prior published base: `28305356916d634089b171e8b5b6fe5c683487b0`. Draft checkpoint `1981836` was committed and pushed at the user's explicit request to publish all current work, including work in progress. Resumed protocol verification and strengthened tests are published in `fb44e96`. Decoder adapter source is published in `76e71ae`; expanded tests and six-lens review are published in `6d35c77`.

The checkpoint includes these three artifact paths:

- `engine/transport/factory_gateway_protocol.go`
- `engine/transport/factory_gateway_protocol_test.go`
- `engine/transport/testdata/factory_gateway_python_frame.json`

A separate [actual-handler fixture](clean-room/verification/2026-11-01-actual-exchange.md) now joins the private exchange to real Bifrost handler/core/local HTTP transport in isolated distinct-UID processes; its routing, provider, authorization and custody services are synthetic.

The parser preserves exact Python request bytes for hashing and validates bounded envelopes, duplicate/unknown fields, frozen identities, output limits, leases and the reserved UTC day. It grants no spending authority. The source-only exchange handler uses the parser and adapter, and the listener source is included in the revised installer; production startup remains unimplemented and unqualified. Its Linux fixtures and selected parser/governed-embedding tests pass; six-lens source review found no actionable issues. Complete ingress qualification remains open.

After resuming, all seven parser test functions and four existing governed-call/native-HTTP groups pass on the actual composed Linux source. The previously unrun rebound-duplicate test now passes. A digest-check mutant initially survived because another validation masked it; a new same-size content substitution rejects it. Three isolated call-to-binding mismatch tests were added. Ten independent overlay guard mutants are rejected by runtime assertions; production parser source is unchanged. Dedicated source review completed seven independent in-process lenses with no retained findings. This is parser-component evidence only, not production startup qualification. See [protocol evidence](clean-room/verification/2026-11-01-gateway-protocol.md).

Current protocol SHA256 values:

- Parser: `adc8f44509f21723cdc02cc3e5251f78152c22ff3593507ece00eda938111ded`
- Tests: `7d5c51d34aaf1a350f4ae8791a8af7339c899a5d38b7915fd7647c259d009449`

Resume metadata: `/tmp/sfactory-composed-gateway-stage.json`. Retained isolated Linux source/toolchain/cache stage: `/home/bo/sfactory-gateway-composed-20261101-tlgy0o91` on `hermes-control`. All current parser tests are copied there and verified. The parser source manifest contains1,894 files; its SHA256 is `e771666daf592836b7e03e7507be4096ba62360ffec6e42f652e187033356a34`. The older1,891-file manifest remains the pre-parser checkpoint. Subsequent retained decoder characterization and adapter sources change the stage; see [decoder evidence](clean-room/verification/2026-11-01-gateway-chat-decoder.md) and note that its 1,895-file manifest predates the three new adapter source/test files. Revalidate source identities and make a fresh manifest before reuse. The task-owned Go build cache was cleared to restore host disk space; source, module archives and evidence remain, but Go builds must regenerate their cache.

## Gateway completion checkpoint

Bifrost source checkpoint `be86704` adds a Linux-targeted completion witness and an installer for the actual middleware and streaming handler. It is a source-only work-in-progress, not a private listener or production admission. Fresh isolated Linux tests passed for the witness and actual middleware/stream scenarios, including a race-enabled run; unpatched controls failed the relevant protected cases. Installer replay refused to alter an already patched source, and a fresh reconstruction reproduced the tested files. Test logs and stage metadata are retained under `/tmp/sfactory-witness-*` and the isolated Linux stages referenced by those metadata files; these temporary paths may not survive cleanup.

The resumed independent review confirmed and the source fix `cde48ea` addressed two protected stream false-success paths involving hook and serialization errors. Original-owner cancellation and composed native-ingress compatibility have focused tests; see [completion evidence](clean-room/verification/2026-11-01-gateway-completion.md). The witness does not by itself prove authenticated private ingress, physical-call closure, arbitrary plugin descendant cleanup, route custody or production launch. Do not infer success solely from stream EOF or `[DONE]`.

The public Ollama Enterprise pricing page mentions user and API-key cost budgets, but does not establish the required hard in-flight, per-task and fee bounds. Account availability and contract details remain unverified; see [provider recheck](clean-room/verification/2026-11-01-provider-envelope-recheck.json).

The protected gateway cancels a stalled response read at the shorter Root deadline; distinct-UID synthetic expiry and v1/v2 success fixtures passed on the installed source. See [stream deadline evidence](clean-room/verification/2026-11-01-root-stream-deadline.md). The [stream close checkpoint](clean-room/verification/2026-11-01-gateway-stream-close.md) bounds read/close joining and poisons the gateway if either remains unjoined. A [blocked-router regression](clean-room/verification/2026-11-01-blocked-router-deadline.md) now proves bounded failure and poisoned-process refusal at the Root deadline. The blocked goroutine can remain alive; termination and cleanup of the gateway and its descendants still require watchdog and egress-fence qualification.

## Remaining work, in order

1. Qualify the source-only private gateway exchange handler (`a3869c5`; [evidence](clean-room/verification/2026-11-01-private-exchange.md)) and implement its dedicated production bootstrap. The revised pinned source installer includes the listener source, but does not create or run a listener; the earlier [executable build](clean-room/verification/2026-11-01-exchange-installer.md) predates it. Authenticate the broker peer, acquire the existing one-use owner root, retain its context through the real auto/governance/embedding/classifier/answer pipeline, join all streams, and acknowledge durable capture before returning. Keep MCP/tool execution Goose-owned. Bind the current route snapshot and resolve semantic startup warmup ownership. A [governance visibility fixture](clean-room/verification/2026-11-01-gateway-vk-visibility.md) shows context-only keys are readable by transport hooks; production plugin and log-sink custody remains unqualified. The historical qualification bootstrap selects a different route and cannot substitute for this integration. The [Root scope-preimage prerequisite](clean-room/verification/2026-11-01-scope-preimage.md) is implemented as a read-only, broker-only interface. Its native socket, broker and wallet join now has [synthetic-configuration evidence](clean-room/verification/2026-11-01-wallet-root-gateway-join.md); production Root construction, live revocation and custody remain unqualified.

2. Obtain supported, affordable **pre-dispatch all-path provider charge bounds** for the retained hosted route: rendered/tokenized input, supported output/reasoning limits, attempts and fees. Published token rates and post-response usage do not establish an enforceable input bound. The rated live branch is explicitly covered by [denial evidence](clean-room/verification/2026-11-01-rated-live-deny.md); existing evidence does not support live admission. See [provider recheck](clean-room/verification/2026-11-01-provider-envelope-recheck.json).
3. Complete remaining native owner-outage, unknown-Docker, daemon/host-loss and production custody/launch qualification without weakening existing gates or disturbing shared services.
4. Freeze the representative 20-task suite and both variants against identical models, route configuration, budgets, tariff and independent acceptance checks. Run three repeats per task/variant: **120 total attempts**. Respect the aggregate daily cap across days.
5. Require every safety regression to pass, no decline in accepted-task count, at least **10% lower median audited usage-rated cost per accepted task**, and no more than **10% higher median completion time**. Missing evidence or a failed gate leaves Phase 11A incomplete and the baseline retained. Keep the candidate disabled until the complete gate passes.

Work has resumed. Preserve all ledgers, failed-attempt evidence and isolated stages. Paid calls and activation remain subject to the unresolved bounds and launch gates above.
