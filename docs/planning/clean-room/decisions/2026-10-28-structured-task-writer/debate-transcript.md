# Debate transcript

Three reviewers: Goose/Rust harness, application security, contrarian operations. Prior user-authorized tool-boundary review continued under the implementation skill. Root moderated; inherited available models used. Three independent research briefs, shared ledger, three position papers, one synthesis and three adversarial responses. Consensus reached; no live calls during debate.


---

## brief.md

# Bounded task artifact writer

Continue the already authorized restricted factory-owned Goose/MCP approach. Actual attempt3 proves Bifrost auto MEDIUM/DeepSeek Flash streams reach the host gate; the actual shell command is refused by execution policy because source syntax includes characters denied globally by `policy::evaluate_at`. No artifact was released. Retain all unknown fences and shell policy.

Choose between (A) one factory-owned structured `write_files` MCP tool limited to exactly `hello.py` and `test_hello.py`, (B) asking the model to encode source into shell-safe strings, or (C) loosening the shell filter. No new vendor, dependency, runtime, model or provider config. Scope is the owned uncapped INT-LOOP task, with no production activation claim.

Proposed A: trusted host pins schema/task/initial prompt and exact provider tool call; fsync dispatch/tool fences precede effects; already-owned network-none executor runs a fixed read-only factory writer, without shell or executing generated source. It accepts only the two fixed names and bounded UTF-8 content, creates exclusive no-follow files, and returns fixed non-content status. Generator/executor roots stop and same-slice emptiness is verified before host snapshots allowed files. Host-held independent challenge runner uses read-only snapshot in separately owned bounded containers; exact evaluated hashes must match committed blobs. Human action-bound promotion stays required. Existing key, auto router and shared services/data remain unchanged.

Review primary current local evidence: execution/src/policy.rs; nuc_factory_write_files.py and its tests; factory file relay; actual Goose worker/service/request schema; batch guardian/recovery; evaluator and task helper. Verify exact source and tests rather than memory. Evidence must distinguish current source facts, actual NUC observations and proposed properties. Unknown/partial writes must quarantine the attempt with no overwrite, restart or automatic retry.

Decision: Does A fit the approved factory tool boundary? What exact negative/positive/recovery controls are required before a fresh live attempt? Which limitations remain production-only?

---

## research-harness.md

# Goose and runtime integration research

## Material facts

1. The current shell policy rejects characters including parentheses, braces, backslashes and `<` anywhere in a command, before interpreting shell quotes ([policy.rs](../../../../../clean-room/crates/execution/src/policy.rs#L189)). Attempt 3's persisted tool-result digest identifies `policy_denied`, and a local boolean classification of its recorded arguments found at least one denied character. Both Bifrost calls ended in tool calls, so the existing one-tool flow withheld the second call; no task file was created ([attempt evidence](../../verification/2026-10-28-live-intloop-attempt.md)).
2. The current protected Goose fixture advertises exactly `factory__shell` and routes MCP `tools/call` to its service; its test observed an actual Linux Goose tool exchange, but the present worker hardcodes the shell schema and name ([worker](../../../../../clean-room/tests/fixtures/nuc_goose_relay_worker.py#L31), [Goose boundary fixture](../../verification/goose_factory_boundary_spike.py#L25)). This is a replaceable task fixture interface, not evidence that a new writer has already been admitted.
3. The current live service pins the initial request and tool schema, binds a validated provider tool ID and arguments, durably fences tool dispatch before execution, and compares the next message to host-owned history ([live service](../../../../../clean-room/tests/fixtures/nuc_live_goose_service.py#L10)). Both this service and the SSE parser currently hardcode `factory__shell`; simply adding an MCP tool would fail the gate ([SSE parser](../../../../../clean-room/tests/fixtures/nuc_bifrost_stream.py#L75)).
4. The proposed writer is a standalone, unregistered fixture. It validates exactly two filenames, bounded UTF-8 contents and no NULs; opens `/work` without following the final symlink; writes exclusive temporary files and links without overwrite, then emits a fixed result ([writer](../../../../../clean-room/tests/fixtures/nuc_factory_write_files.py#L6)). Its matching proposed relay rejects wrong arguments and repeat IDs ([file relay](../../../../../clean-room/tests/fixtures/nuc_structured_file_relay.py#L6)). Unit tests cover bounded inputs, refusal of extra names, no overwrite and ordinary rollback; they do not prove power-loss atomicity, crash cleanup or live MCP integration ([writer tests](../../../../../clean-room/tests/fixtures/test_nuc_factory_write_files.py#L1)).
5. The batch fixture records ownership before starting network-none, capability-dropped UID 1001 roots ([batch guardian](../../../../../clean-room/tests/fixtures/docker_batch_guardian.py#L141)). Independent evaluation stops generation roots, creates a hash-bound snapshot and runs host-selected challenges against a read-only candidate in separate owned containers ([evaluator](../../../../../clean-room/tests/fixtures/nuc_int_loop_evaluator.py#L31)). Those controls are separate from the proposed writer and must run on its actual output.

## Options and preliminary recommendation

**A: fixed structured writer.** Recommend for this task only. It gives Goose a typed file operation and moves model-generated text as data into a fixed executable, without weakening shell policy. Pin the exact `factory__write_files` schema and expected task at bootstrap; explicitly wire that schema through the Goose MCP shim, SSE parser, durable service, and the precreated executor. The current shell-specific implementation will reject it until those reviewed changes are made. An executor failure or lost acknowledgement is unknown, and the run must not restart the writer.

**B: encoded shell strings.** This keeps the existing tool but pushes encoding correctness onto the model, retains opaque shell execution and may fail the global syntax filter. It does not give the gate a filename/content schema or solve trusted result correlation. It is a poor fit for this small bounded task.

**C: loosen shell filtering.** This broadens the command language and the security review far beyond the two allowed artifacts. Existing confinement evidence does not prove arbitrary shell syntax safe, especially for descendants and worktree escape. Reject as unnecessary for this task.

Before any fresh live call, exercise real Linux Goose with the exact writer schema and synthetic upstream against the actual batch, peer gate and writer; verify exact two-file success, malicious names, extra fields, oversized/invalid Unicode, preexisting files and symlinks, ID/argument mismatch, duplicate/concurrent calls, lost acknowledgement and process death. Confirm both owned roots are stopped and the same slice is empty, retain partial/unknown states without retry, and independently evaluate a frozen candidate with no helper or credentials mounted. Compare evaluated hashes with committed blobs and retain action-bound human approval for promotion. The writer's current cleanup is best effort and its directory is fsynced before temporary links are removed; crash-durability and partial-write recovery must be tested, not inferred from the unit tests. JSON duplicate-key rejection must also be enforced at both model-stream parsing and the writer boundary.

This recommendation does not establish durable production task provisioning, production ledger migration, fully general Goose protocol support, host/daemon-loss recovery, independent production promotion authority or a shipped implementation. The user waived monetary caps for this run only; no general production budget policy follows from the fixture.

---

## research-security.md

# Application security: bounded task artifact writer

## Current evidence

1. The existing policy rejects characters used in ordinary Python source regardless of quoting; it describes itself as a partial shell filter, not a sandbox. Loosening it changes an established security check without adding containment. [policy.rs](../../../../../clean-room/crates/execution/src/policy.rs)
2. The fixture writer accepts only two exact names, nonempty UTF-8 content up to 32,768 bytes apiece and no NUL; it uses a directory descriptor, exclusive no-follow temporary files and hard links that refuse overwrites. It writes sequentially, so crash or cleanup failure can leave partial files or temporary links; it is not a two-file transaction. [nuc_factory_write_files.py](../../../../../clean-room/tests/fixtures/nuc_factory_write_files.py)
3. `FileRelay` records one exact provider ID and arguments and consumes it before invoking the executor. This is in-memory only; the existing durable fence binds an argument digest and records tool-unknown before effects. Both must be wired together, with no automatic replay after interruption. [nuc_structured_file_relay.py](../../../../../clean-room/tests/fixtures/nuc_structured_file_relay.py), [nuc_run_fence.py](../../../../../clean-room/tests/fixtures/nuc_run_fence.py)
4. Current live code remains shell-specific: the MCP worker advertises/calls `shell`, the stream parser requires `factory__shell`, and the service pins the shell schema and reconstructs that name. The file tool schema and relay are fixtures, not an integrated live path. The JSON Schema `maxLength` counts characters while the writer enforces bytes; the whole transport also has a 65,536-byte bound. [nuc_goose_relay_worker.py](../../../../../clean-room/tests/fixtures/nuc_goose_relay_worker.py), [nuc_bifrost_stream.py](../../../../../clean-room/tests/fixtures/nuc_bifrost_stream.py), [nuc_live_goose_service.py](../../../../../clean-room/tests/fixtures/nuc_live_goose_service.py)
5. The evaluator freezes only after `Batch.stop`, hashes a private snapshot, runs each challenge in a fresh owned container with a read-only snapshot, tears it down, and compares snapshot hashes before publication. Finalization checks committed blob hashes against the evaluated files. This supports a scoped fixture, subject to successful actual owner-loss and evaluator gates; generated tests can self-report success. [nuc_int_loop_evaluator.py](../../../../../clean-room/tests/fixtures/nuc_int_loop_evaluator.py), [nuc_int_loop_task.py](../../../../../clean-room/tests/fixtures/nuc_int_loop_task.py)

Local writer unit tests passed 3/3 and relay tests 2/2 in this review. These are synthetic local tests, not proof of Goose MCP integration or an actual writer execution. The brief reports a real attempt3 provider response and shell-policy refusal; that observation alone does not establish file-tool behavior.

## Options

| Option | Security and operational assessment |
| --- | --- |
| A: fixed structured writer | Recommend for this task. Narrow authority to two fixed filenames and content, no shell, same owned executor, explicit provider-call and durable-fence binding. Requires the integration and recovery controls below. |
| B: encode source in shell-safe strings | Retains broad shell execution and introduces quoting/decoding interpretation and brittle source handling. Does not improve the authority boundary; existing policy may reject required syntax. |
| C: loosen shell filter | Broadens all commands using that policy and risks reintroducing syntax bypasses. Not justified for producing two files. |

## Required spike and controls

Before a fresh live attempt, implement a synthetic end-to-end Goose/MCP test that proves the worker advertises only the intended write tool, the pinned initial schema and prompt agree with it, the parser accepts only the exact function and stable provider ID, and the service binds the exact parsed arguments to one durable pre-effect fence. Tool substitution, changed IDs/content, duplicate JSON keys, extra files, traversal, symlinks, existing target, malformed/empty/oversized Unicode, NUL, aggregate frame overflow and replay must fail before writes. Positive controls should prove both exact bytes and a fixed, non-content response. Explicitly test service restart and owner loss before, during and after each file write: partial, timed-out, ambiguous or cleanup-failed attempts remain quarantined, with no overwrite, resume, or automatic retry; no result is released until whole owned executor/worker teardown and the correct slice is empty. Do not assume rollback makes a crash atomic.

Exercise the actual isolated executor and manager recovery with a synthetic request, then independently evaluate a frozen read-only snapshot and verify committed blobs match. The executor must receive only the writer and task workspace, with network disabled and no credential, socket, Git metadata, evaluator, or holdout mount. Verify resource and frame limits align across MCP, relay and writer. Never run candidate code on the host. Promotion remains a separate human action-bound decision.

## Limits

The fixed two-name writer is a task-specific capability, not generic filesystem confinement or production authority. A successful scoped INT-LOOP would not establish production journal and identity integration, holdout provenance, independent brake/recovery, migration, or production verification gates. Host bo, Docker daemon and the existing Bifrost service are trusted in this scoped experiment; UID 1001 workload remains untrusted.

---

## research-operations.md

# Operations research: bounded task writer

Position: provisionally prefer **A**, a single task-specific structured writer, only after the existing supervised fixture proves one-shot execution, quarantine and exact candidate import. Do not weaken the shell policy or infer a successful task from a successful tool call. This decision is limited to the two-file INT-LOOP fixture; it is not approval for a general file API or production activation.

## Evidence ledger

1. The current shell policy rejects several source characters anywhere in a command, before its segment checks. Encoding source to evade that check would introduce a second parser and keep operations dependent on fragile shell syntax. [policy.rs:189–203](../../../../../clean-room/crates/execution/src/policy.rs#L189-L203)
2. Actual NUC attempt 3 reached the Bifrost route twice; its first stored result matches `policy_denied`, a second tool request was withheld and the fence remains `unknown1`. Recovery receipts and an empty slice are recorded, but no candidate exists. Earlier attempts retain `unknown0`. This is evidence of a real boundary failure, not a failed writer experiment. [live attempt evidence](../../verification/2026-10-28-live-intloop-attempt.md#L5-L11)
3. The proposed writer validates exactly two names and bounded nonempty UTF-8 values, opens its directory without following symlinks, creates exclusive random temporary files and hard-links final names. Its best-effort cleanup swallows unlink errors; a crash between links, cleanup or fsync can leave partial files or hidden temporary entries. A refused status is therefore not proof of a clean directory. [writer:6–35](../../../../../clean-room/tests/fixtures/nuc_factory_write_files.py#L6-L35), [tests:4–17](../../../../../clean-room/tests/fixtures/test_nuc_factory_write_files.py#L4-L17)
4. The fresh-run fence persists `unknown` before inference and tool effects and binds tool ID and argument digest. It is explicitly fixture-only and per-run: a different fresh run is not proof that an older unknown effect did not occur. [run fence:59–86](../../../../../clean-room/tests/fixtures/nuc_run_fence.py#L59-L86)
5. The evaluator stops the batch before importing two no-follow regular files and later checks snapshot hashes, but its current `freeze` iterates only those names; it does not reject extra directory entries. Finalization compares evaluated digests to committed blobs and requires human promotion approval, but that later repository check cannot detect extras that the importer omitted. [evaluator:25–48, 81–86](../../../../../clean-room/tests/fixtures/nuc_int_loop_evaluator.py#L25-L48), [task finalization:19–37](../../../../../clean-room/tests/fixtures/nuc_int_loop_task.py#L19-L37)
6. The separate UID/key brake fixture stopped both exact batch roots after its synthetic Goose relay and journal unit was killed, including a pending-lock admission closure; the same slice reported empty. This does not prove production identity, real gateway independence or host/daemon-loss recovery. [authenticated batch brake evidence](../../verification/2026-10-28-nuc-authenticated-batch-brake.md)

## Options

| Option | Operational benefit | Failure and scope cost | Position |
|---|---|---|---|
| A: fixed structured writer | Exact names, bounded data and no shell execution; isolates authoring from evaluation | New dispatch schema, write durability and recovery boundary; partial or unknown outcomes require quarantine | Prefer narrowly, conditioned on controls below |
| B: encode into shell-safe strings | Avoids a new named tool | Adds quoting/decoding semantics and can route around the very policy causing the refusal; harder to audit and repeat | Reject |
| C: loosen shell filter | Small immediate code change | Broadens all shell-capable paths beyond this task; difficult to bound unintended commands | Reject |

## Required controls and gaps

- Fail closed on any unknown writer, response, or cleanup outcome. Preserve the existing attempt fence and manifest; do not delete hidden remnants, overwrite, automatically retry, or start a fresh generation as an implicit recovery. A separately authorized new generation must not be described as reconciliation of an earlier unknown effect.
- After exact owned roots stop and the original worker slice inode is verified empty, enumerate the entire candidate directory without following links. Require exactly the known baseline README and the two regular single-link output files; reject hidden `.factory-*`, extra files, directories, symlinks and special files. Validate baseline identity/content too. The current two-name importer does not do this.
- Treat the writer as a capability, not a generic patch interface: fixed catalogue, schema, exact tool name and provider call identity, bounded complete arguments, fsynced consume before the first effect, one execution per attempt, fixed status with no generated content. No worker-selected mount, executable, filename, options, or hidden evaluator material.
- Cover crash after each temp creation, file sync, link, directory sync, cleanup, and tool-result persistence; inject unlink/fsync failures and verify no result/snapshot/commit escapes. Probe replay, duplicated JSON keys, non-UTF-8, NUL, byte versus character limits, full request limit, nested/symlink/hardlink paths, and both output orderings. Existing unit tests do not establish those outcomes.
- Verify exact snapshot hashes in isolated networkless challenge containers, tear down and observe empty after every challenge, and compare evaluated bytes to actual committed blobs. Keep the host challenge expectations and approval credentials outside worker mounts. Tests must exercise wrong candidate, hidden-extra, modified snapshot, cleanup failure and forged result as negative controls.
- Serialize all uses of the shared worker slice with a trusted lifecycle owner. Same-UID Docker authority, manager or daemon loss, filesystem and power-loss durability, durable operator provisioning and independently authenticated production recovery remain outside this fixture's proof.

## Bounded next spike

Without provider or production calls, run the actual Goose/MCP adapter and fixed writer in the supervised task-owned container with a benign synthetic two-file payload. Assert exactly one durable effect, stop both roots, prove the exact candidate entry set and snapshot hashes, run host-selected hidden positive and negative challenges, and compare committed blobs. Repeat with injected crash at each durable transition and a missing/failed cleanup receipt; every ambiguous case must remain quarantined and unable to publish or dispatch again. Include a synthetic explicit wrong-name/second-call canary to show rejection. Preserve the shared slice and all prior manifests; no further live run follows automatically.

---

## evidence-ledger.md

# Evidence ledger — structured task writer

Evidence grade: **ADEQUATE for a bounded task-specific implementation and synthetic spike; INSUFFICIENT for production activation**. Research is current primary local source inspection and actual dated NUC observations, not new vendor or release claims. Research briefs retain exact source links.

Questions: choose A/B/C; define minimum integration, replay, partial-write, teardown, immutable evaluation and human promotion gates.

| Verified fact | Primary source | Relevance |
| --- | --- | --- |
| Existing shell policy rejects source characters before quote interpretation | `clean-room/crates/execution/src/policy.rs` | Real task cannot use ordinary source-writing shell; do not remove check silently |
| Actual attempt3 had two auto MEDIUM/Flash streams; tool was policy-denied, second tool withheld; no candidate | `verification/2026-10-28-live-intloop-attempt.md` | Local failure is reproduced; no successful artifact claim |
| Protected MCP worker, SSE parser and service currently pin shell tool | `nuc_goose_relay_worker.py`, `nuc_bifrost_stream.py`, `nuc_live_goose_service.py` | New writer requires deliberate whole-path wiring |
| Proposed writer has two exact paths, UTF-8 byte limits, exclusive no-follow temp files and no-overwrite links | `nuc_factory_write_files.py`, tests | Narrow bounded capability, no shell; pair is not atomic |
| Proposed FileRelay binds provider ID/exact files and consumes once in memory; durable RunFence is separate | `nuc_structured_file_relay.py`, `nuc_run_fence.py` | Both must be connected; unknown effects cannot replay |
| Evaluator stops generation, snapshots no-follow files and runs separate read-only challenge containers; finalizer compares committed blobs | `nuc_int_loop_evaluator.py`, `nuc_int_loop_task.py` | Stronger scoped artifact evidence; current importer must reject extras/changed baseline |
| Actual NUC bad-candidate and owner-SIGKILL controls withheld result and cleaned roots | `verification/2026-10-28-nuc-isolated-int-loop-evaluator.md` | Existing recovery base, not structured-writer proof |
| Actual authenticated two-root brake works after synthetic relay/journal outage | `verification/2026-10-28-nuc-authenticated-batch-brake.md` | Independent scoped stop; production/host/daemon loss not established |

All three personas independently prefer A for this task and reject encoded-source workarounds and shell-policy weakening. No factual contradictions found. Open design disagreements: must cleanup be transactionally atomic, or is durable unknown plus quarantine sufficient? Are per-file limits enough, or must all JSON frames share an aggregate byte contract? How strict must candidate entry-set/baseline verification be? Does this scope imply production or generic file API approval? Root moderates because no specialized moderator agent type is available.

Unsettled proof: duplicate JSON rejection, byte/frame agreement, malformed Unicode, crash and cleanup injection, real Goose MCP writer wiring, exact directory/baseline snapshot verification, postwriter owner-loss handling, actual live artifact and private evaluation. These are test/implementation gates, not facts inferred from consensus. All previous unknown fences stay preserved. No monetary cap or key/router settings are introduced.

---

## position-harness.md

# Position: admit one task-scoped structured writer

## Recommendation and evidence grade

Choose **A**, a factory-owned `write_files` tool for this task only. The evidence is **adequate to build and test a bounded integration, but insufficient for production activation or another live request today**. Keep the existing shell policy, all three prior unknown fences and the existing Bifrost `auto` routing. Do not select a model manually. The user waived monetary caps for this INT-LOOP only; this position does not create an uncapped production default.

The proposal is sound if treated as a new capability with its own strict end-to-end gate. It is risky if treated as merely adding a Python helper: the current Goose advertisement, stream parser and trusted host service are shell-specific, while the proposed writer and file relay have not been exercised through that path. A successful unit test of an unregistered helper cannot establish that Goose can invoke it, that its arguments came from the actual provider response, or that its files survived an owner failure safely.

## Evidence-backed rationale

The actual task failure has a direct local cause. `policy::evaluate_at` rejects source-relevant characters before interpreting quoting, including parentheses, braces, backslashes and `<` ([policy.rs](../../../../../clean-room/crates/execution/src/policy.rs#L189)). The recorded first tool result matched `policy_denied`, and a local classification of its provider arguments found denied syntax. The model then requested another tool, which the one-tool runtime withheld; the run produced no files ([live attempt evidence](../../verification/2026-10-28-live-intloop-attempt.md)). This is not a reason to weaken the shell parser. It shows the requested operation does not fit that parser's supported language.

The current worker advertises only `shell` and forwards that MCP call's arguments over the Unix relay ([worker](../../../../../clean-room/tests/fixtures/nuc_goose_relay_worker.py#L31)). The host service pins `[TOOL]`, records a provider tool call, fences execution and compares a continuation with host-owned prior messages ([live service](../../../../../clean-room/tests/fixtures/nuc_live_goose_service.py#L10)). The SSE collector also explicitly checks `factory__shell` ([stream parser](../../../../../clean-room/tests/fixtures/nuc_bifrost_stream.py#L55)). Therefore the writer requires a coordinated schema change across the actual worker, collector and service. A task-specific helper that is absent from any one of those locations is dead code or, worse, a second unauthenticated path.

The proposed writer checks the two names and UTF-8 byte limits, opens the work directory with `O_NOFOLLOW`, creates temporary files exclusively, links without overwrite and returns a fixed status ([writer](../../../../../clean-room/tests/fixtures/nuc_factory_write_files.py#L6)). Its file relay compares the provider ID and exact argument object before a single in-memory consume ([file relay](../../../../../clean-room/tests/fixtures/nuc_structured_file_relay.py#L12)). These are useful building blocks, not a single atomic transaction: the two links are separate, rollback is best effort and a process or host failure can leave partial or temporary files. A durable unknown state plus quarantine is the correct response to that ambiguity.

## Strengths

1. **The capability is proportional to the task.** The host-selected schema can require exactly `hello.py` and `test_hello.py`; source is data, and the fixed writer need not execute generated code. Exact names and byte bounds are more assessable than an arbitrary shell command.
2. **The existing trust boundary can be reused.** A protected service can correlate the single pending provider tool ID to the worker's MCP request, then run the fixed writer through the already-owned executor. The worker must not submit a result attestation. Current batch creation records intent before creating network-none, capability-dropped roots ([batch guardian](../../../../../clean-room/tests/fixtures/docker_batch_guardian.py#L141)).
3. **The uncertainty model is conservative.** `RunFence` persists an unknown stage before inference and tool dispatch; it rejects subsequent attempts from that stage ([run fence](../../../../../clean-room/tests/fixtures/nuc_run_fence.py#L59)). It is suitable as an isolated run fence, not proof of migrated production budget or task authority.
4. **The evaluator is independently useful.** Existing evaluation stops generation, copies and hashes candidate files, runs challenges in read-only candidate containers, then checks hashes again before publication ([evaluator](../../../../../clean-room/tests/fixtures/nuc_int_loop_evaluator.py#L31)). The host-only challenge controller prevents the writer's success message from deciding acceptance.

## Ranked concerns and alternatives

**1. False provider or tool provenance — highest.** The writer must not accept a worker's arbitrary files as authoritative merely because they arrive through MCP. Require a complete bounded SSE response, a stable response ID and allowed served model, a single `factory__write_files` tool ID and duplicate-free parsed arguments. The host records that exact ID and argument digest before exposing the response. Its next tool request must match; only its captured writer result can enter the subsequent conversation. An untrusted worker-published result or a different ID must cause zero writes. Do not solve this by adding a general write endpoint to the worker.

**2. Durable unknown versus in-memory relay.** `FileRelay.used` disappears on restart ([file relay](../../../../../clean-room/tests/fixtures/nuc_structured_file_relay.py#L12)). Call `RunFence.begin_tool` before starting the fixed executor, and persist a result only after validating the actual bounded writer response. A timeout, disconnect, crash or failed fsync quarantines the task directory and consumes the attempt. A new process must not reconstruct a fresh relay and silently replay. Provider sends follow the same unknown-before-effect rule. This does not provide exactly-once effects across every crash; it deliberately provides no automatic repeat.

**3. The initial request and transcript must stay task-bound.** `TaskRequestPin` currently permits only narrowly formatted volatile time and workdir while comparing stable fields to a host-held snapshot ([request pin](../../../../../clean-room/tests/fixtures/nuc_task_request_pin.py#L6)). Generate and verify a fresh synthetic snapshot for the writer schema and exact task text. After the actual request is admitted, retain its exact accepted structure, reconstructed validated assistant call and actual tool result for the second turn. The fence hashes a request but does not independently validate its conversation: keep that comparison in the trusted service ([run fence](../../../../../clean-room/tests/fixtures/nuc_run_fence.py#L59)). Reject altered user, system, schema, assistant ID/arguments or tool result before a provider send.

**4. Pair publication and envelope sizes are not yet proven.** Per-file limits alone do not bound the JSON envelope: escaping, Unicode, schema and prior transcript consume bytes too. Establish one explicit aggregate request/frame budget across provider response, Unix transport, MCP request and executor stdin, in addition to per-file UTF-8 limits. Reject duplicate keys and invalid Unicode at every trust boundary. Test the maximum accepted case and the first rejected byte, including escaped and multibyte content. If both maximum-sized files cannot fit, document and enforce the smaller effective limit; do not silently truncate.

**5. Containment and evaluation are separate gates.** Both owned roots must be sealed before start and stopped before a candidate snapshot. A crash between links, lost writer reply or interrupted cleanup must leave no evaluated or promoted result; it does not have to make the pair transactionally atomic if all ambiguous contents are quarantined. A clean result still needs the exact allowed entry set and unchanged baseline, isolated challenges and committed blob hashes equal to evaluated hashes. Host or Docker daemon compromise and production recovery are outside the proven fixture boundary.

## Missing considerations and concrete changes

The MCP response is not an authority channel: preserve the provider's tool ID on the host even if Goose's MCP request uses a different local ID, and correlate only the one outstanding approved call. Parameterize the parser with a trusted immutable tool name; reject multiple tools, wrong indices, changed response identity, extra properties and incomplete stream completion. The writer must independently reject duplicate JSON keys, as the raw executor boundary should not depend on upstream parsing alone.

Add a fresh `write_files` schema, a task-specific MCP shim mode, a service-selected `FileRelay`, and a fixed executor writer mounted read-only. Do not accept executable paths, workdir, mount options, filename lists or policy from model input. Test synthetic actual Linux Goose end-to-end with positive writes, forbidden path and symlink cases, preexisting files, incomplete UTF-8, invalid or duplicate JSON, multiple IDs, argument alteration, concurrency and failure injection at each file operation. Include process death before and after each link, dropped acknowledgements, owner loss and independent brake. Verify no outside write, no second executor start and no automatic retry. Run the existing separate evaluator against a frozen snapshot only after the roots are demonstrably empty.

## Hard stance

- No live writer dispatch until actual Linux Goose, the pinned schema, durable fence, fixed executor and authenticated peer path pass synthetic positive and adversarial controls together.
- Never repeat an ambiguous inference or write, and never publish or evaluate an ambiguous partial candidate as successful. Preserve the prior unknown records.
- Do not loosen the shell filter or expose a general filesystem API to make this task work. A successful fixture produces an evaluated candidate, not production activation or human promotion approval.

---

## position-security.md

# Application-security position: structured task writer

## Recommendation

Choose option A for this one owned INT-LOOP: a factory-owned typed `write_files` capability, restricted to exactly `hello.py` and `test_hello.py`, invoked inside the already supervised, network-disabled executor. Treat it as a new capability requiring complete worker, provider-stream and host-gate integration and independent verification. Preserve the existing shell policy and prohibit shell execution for the writer. The evidence supports a bounded synthetic implementation and spike; it does not establish production readiness. The [shared ledger](evidence-ledger.md) records the dated observations and remaining proof.

This recommendation is conditional on durable pre-effect fencing, quarantine of every partial or ambiguous outcome, teardown before artifact release, and independent hash-bound evaluation. None of those is optional because the intended output is executable code controlled by an untrusted workload. Host bo, Docker daemon and the existing Bifrost service are trusted for this experiment; UID 1001 is not. A fixed writer narrows the authority presented to that workload but does not defend against compromise of those trusted components.

## Assessment and strengths

The real attempt described in the [attempt record](../../verification/2026-10-28-live-intloop-attempt.md) reached the provider and produced a shell call that policy refused. That is evidence of a specific usability mismatch, not evidence that the policy malfunctioned. The policy rejects source characters globally and explicitly describes its shell checks as a partial filter, not a sandbox ([policy source](../../../../../clean-room/crates/execution/src/policy.rs)). Encoding arbitrary source into shell-compatible strings retains shell interpretation, creates a fragile encoding and decoding path, and leaves more authority exposed than the task needs. Weakening the filter for this task would broaden a shared rule without delivering stronger isolation. Neither is preferable to a fixed operation.

The existing [writer fixture](../../../../../clean-room/tests/fixtures/nuc_factory_write_files.py) already validates the two fixed names, rejects empty content and NUL, applies a UTF-8 byte limit, and uses exclusive no-follow temporary files and no-overwrite hard links under an opened workspace directory. Its success response contains status rather than candidate content. The [file relay](../../../../../clean-room/tests/fixtures/nuc_structured_file_relay.py) binds a provider call identifier to exact validated arguments and consumes it before calling its executor. The separate [durable fence](../../../../../clean-room/tests/fixtures/nuc_run_fence.py) records the tool's identity and argument digest before an effect, then records completion only after the result. Wired correctly, these layers constrain both what can be written and which observed provider call authorizes it.

The [evaluator](../../../../../clean-room/tests/fixtures/nuc_int_loop_evaluator.py) offers a second, independently held boundary: stop the generation roots, copy and hash an immutable snapshot, execute challenges in separate read-only containers, and verify snapshot and committed blob hashes. The [task finalizer](../../../../../clean-room/tests/fixtures/nuc_int_loop_task.py) compares the evaluated file hashes with the committed blobs. The actual NUC evaluator and recovery observations in the ledger give useful evidence for those existing fixtures, but do not prove the new writer path. Generated unit tests can print misleading success text, so their reported count is not independent evidence; the host-held behavioral challenges remain essential.

## Concerns and changes required

**No shell fallback.** The worker's MCP advertisement and call dispatch, the stream parser's function-name check, the initial request's pinned tool schema, the service's tool-call history, and executor invocation must all agree on the typed writer. Current live components are shell-specific ([worker](../../../../../clean-room/tests/fixtures/nuc_goose_relay_worker.py), [stream parser](../../../../../clean-room/tests/fixtures/nuc_bifrost_stream.py), [service](../../../../../clean-room/tests/fixtures/nuc_live_goose_service.py)). A provider-supplied name, MCP tool substitution, extra fields or argument changes must be refused. No dynamic executable path, filename, command, working directory, environment, or option may be accepted from the model. The fixed executor must run the factory writer directly, not through `sh -c` or an execution shim that interprets a command string.

**Durable unknown and quarantine suffice for this scoped task; atomic two-file publication is not required.** The present writer links two files sequentially. A crash can leave one final name, temporary names, or multiple links; cleanup and directory fsync are not a transaction. Implementing a new atomic directory-swap protocol would add authority and complexity without being necessary if incomplete outcomes are never consumed. The acceptable contract is: durable tool-unknown precedes any write; any interruption, timeout, malformed response, failed cleanup, inconsistent status, or unverified teardown quarantines that unique generation permanently. Do not overwrite, reopen it for writing, automatically retry, evaluate, import, or mark it successful. Only a fully verified success, followed by stopped owned roots and verified empty slice, may advance to snapshot. In particular, a refusal response cannot establish that no bytes were written: refusal after a partial effect is still quarantined. This requires actual crash and teardown tests at every meaningful write/link/cleanup boundary, not merely a unit test that catches an ordinary exception. A later production design may demand stronger transactional guarantees, but this scoped alternative is sound only if the no-release invariant is enforced and evidenced.

**Use one explicit aggregate byte contract.** Per-file limits alone are insufficient: 32,768 bytes each plus JSON syntax, escaping, UTF-8 expansion and protocol envelopes can exceed the 65,536-byte frames in the current path. JSON Schema `maxLength` measures characters, whereas the writer checks encoded bytes. Define a deterministic maximum on the actual serialized UTF-8 bytes at every stage, with sufficient envelope headroom, and require both each file and the entire request to fit before `begin_tool` and before any side effect. A schema may advertise a conservative character bound, but host byte validation is authoritative. Require strict JSON with duplicate-key refusal, valid Unicode, no NUL, exact keys and nonempty strings. Tests must include multibyte and escape-heavy near-limit values, exact-limit and over-limit envelopes, malformed surrogate values and oversized streams. All layers must either accept the same bounded request or reject it before write; truncation or treating rejected bytes as successful content is forbidden.

**Bind the artifact to its generation.** A successful writer response is not an artifact receipt. The trusted evaluator must establish that the generation identity, baseline and exact candidate entry set correspond to the requested task, and freeze only after verified teardown. It must reject extra files, symlinks, hard links, changed baseline content, missing files and evidence from another generation, then hash exactly the bytes executed and imported. The parent's in-progress baseline and generation-binding fix needs its own positive and substituted-generation negative tests. The finalizer must compare committed blobs to the evaluated snapshot, and all candidate execution must remain inside the owned, network-disabled evaluator with bounded output and runtime. Promotion remains separately authorized by the action-bound human channel.

## Verification and hard stances

Before any fresh live request, require synthetic end-to-end tests through the actual Goose MCP worker and host gate: correct listing, exact provider call and continuation, one invocation, byte-for-byte files and fixed status; negative tests for shell/tool substitution, provider ID and argument changes, duplicate keys, unapproved filenames, symlinks, existing targets, malformed and oversized content, fence replay, restart and owner loss. Verify exact executor mounts and absence of credential, provider socket, Git metadata, evaluator and holdout files. Stop both owned roots and verify the intended slice empty before evaluating. Exercise an interrupted writer against the actual supervised NUC fixture and retain all records without automatic cleanup of unrelated resources. These checks must demonstrate behavior, not just pass mocked calls.

I will not accept a shell-filter relaxation, a claimed atomic pair based on best-effort rollback, reuse of an unknown fence, a success response without complete teardown, evaluation of a partial directory, or a claim that these fixtures authorize production. Production identity and journal integration, authoritative provenance and holdout isolation, independent recovery/brake, migration and the remaining verification gates remain separately open. The user’s monetary waiver for this INT-LOOP does not alter those boundaries or change production defaults.

---

## position-operations.md

# Operations position: one bounded writer, preserved uncertainty

## Recommendation

Choose **A**, one factory-owned structured writer for exactly `hello.py` and `test_hello.py`, as a task-specific capability within the already approved restricted Goose tool boundary. The service should accept one provider-bound call, persist its consume fence before any filesystem effect, invoke the fixed writer in the owned executor, and release only a fixed bounded result. Keep source creation, evaluation and promotion as separate stages. Do not broaden the shell filter or add an encoded-source escape route.

This is a conditional implementation decision, not evidence that the present structured path already works end to end. The evidence ledger grades local evidence adequate for implementation and a synthetic spike, but insufficient for production activation. [Evidence ledger](evidence-ledger.md) The actual third NUC attempt reached the provider, returned a policy-denied first tool result, and withheld a second request; it produced no candidate. [Live attempt evidence](../../verification/2026-10-28-live-intloop-attempt.md#L9-L11) The structured writer has local source and tests; its full Goose-to-writer lifecycle needs its own falsifiable proof.

## Hard stance: partial writes are quarantined, not declared atomic

The two output files do not form an atomic transaction. The fixture writes a temporary file, fsyncs it, hard-links its final name, and repeats for the second file; rollback and temporary-file deletion are best-effort. A crash or failed unlink can leave a partial pair, a hidden temporary name, or multiple links. A returned refusal is not proof of rollback. [Writer implementation](../../../../../clean-room/tests/fixtures/nuc_factory_write_files.py#L14-L35) Requiring an atomic pair before even a synthetic attempt would impose a stronger filesystem transaction design than this bounded task needs, and could obscure the actual operational contract. Durable uncertainty plus quarantine is acceptable for the narrowly supervised attempt, **only if** no partial or unknown outcome can be imported, reported as success, retried in place, evaluated or promoted.

The intended sequence is: persist the specific tool call as unknown; execute once; independently verify the writer's complete fixed result and record it durably; stop both exact owned roots; verify the original worker cgroup identity and `populated 0`; then validate and snapshot the candidate. If the process, host-side response, stop receipt, directory sync or fence update is uncertain, retain the manifest, candidate and prior fence for inspection. Do not infer completion from file existence, or infer absence from a timeout. Existing `RunFence` already has an unknown stage before the tool call, but linking that fence to the writer and cleanup is a required integration test rather than an established result. [RunFence](../../../../../clean-room/tests/fixtures/nuc_run_fence.py#L59-L81)

Continuous user authorization permits a separately scoped fresh generation when the supervising agent has reviewed the prior attempt and applies the current task scope; it does not require a new user prompt solely because an earlier generation is quarantined. It does require a new identity, directory, manifest and fence, verified cleanup and exclusive slice admission. A fresh generation must never clear, reset, rewrite or claim to reconcile an earlier `unknown` fence. If the earlier owner or cleanup remains unresolved, do not run another generation on the shared slice. This is a lifecycle rule, not a demand for unnecessary human confirmation.

## Exact import and hidden-file boundary

The importer must enumerate the complete candidate directory after teardown, not just open the expected files. Its current `freeze` opens the two selected names and ignores other entries; the later Git finalizer sees only what was copied into its repository. [Evaluator](../../../../../clean-room/tests/fixtures/nuc_int_loop_evaluator.py#L25-L48), [finalizer](../../../../../clean-room/tests/fixtures/nuc_int_loop_task.py#L19-L35) Before copying, require exactly the original baseline README and the two expected output files, and recheck baseline identity and bytes against the trusted task input. Reject all extra entries, including hidden `.factory-*`, directories, links and special files; reject symlinks, multiple-link regular files, oversized or missing output files. No cleanup of suspect entries should precede this check, because deleting them destroys the evidence of an interrupted or out-of-scope write.

Once this exact set passes, create a host-private snapshot and hash the actual copied bytes. A read-only bind only prevents mutation from inside the evaluator container; the trusted host must also prevent concurrent changes and recheck hashes. Run each host-selected challenge in a fresh, separately owned networkless container without mounting the hidden expected values, evaluation authority, credentials, or `.git`. Tear down and observe the slice empty before publishing a result. Compare every evaluated digest to the actual committed Git blob and keep action-bound human promotion separate. The task helper already performs the blob comparison; that implementation is meaningful only when supplied a trustworthy evaluated snapshot. [Task finalizer](../../../../../clean-room/tests/fixtures/nuc_int_loop_task.py#L26-L37)

## Input and lifecycle controls before a live writer call

Use a single coherent byte contract across the provider SSE fragments, JSON frame, host relay, durable fence, writer stdin and individual files. Both file values need a nonempty UTF-8 byte bound and the entire JSON request needs a distinct aggregate bound, accounting for escaping and framing. Reject duplicate JSON keys, malformed Unicode, NUL, unexpected fields, absent files, alternate names, repeated calls, forged provider IDs and mismatched argument digests before effects. A model-visible schema limit measured in characters does not itself enforce a byte or frame limit.

Required synthetic controls include a positive two-file call and an independent no-call control; same-call replay and second-call refusal; both write orders; wrong names and extra keys; existing-file, symlink and hardlink targets; and capacity boundaries around UTF-8 and JSON escaping. Inject a crash or error at each create, file fsync, link, directory fsync, unlink, tool-result write and cleanup step. Confirm that partial writes, a lost response, a stale or missing receipt, an unobserved engine result, or an owner death never yield a snapshot or success record. Test the actual Goose/MCP adapter, host gate, fixed executor and recovery helper together, not merely writer unit tests.

The authenticated NUC fixture provides useful scoped evidence: after the synthetic Goose relay/journal unit was killed, the independent authenticated brake closed admission, removed its exact roots, and observed the same worker slice empty. It does not establish recovery from host-manager or Docker-daemon loss, production peer provisioning or a hostile same-UID Docker operator. [Brake evidence](../../verification/2026-10-28-nuc-authenticated-batch-brake.md) Keep shared-slice operations serialized by the trusted lifecycle authority, and treat this result as a fixture guarantee under those assumptions.

## Alternatives and scope

Option B, model-encoded source in shell-safe text, makes success depend on a second parser and encourages bypassing the rule that rejected the original command. It retains arbitrary shell authority where the task only needs two file values. Option C, removing the forbidden-character filter, expands the shell boundary across unrelated commands; a two-file task does not justify that risk. The existing filter is applied before quote interpretation, so ordinary source text is a concrete failure mechanism rather than merely an inconvenient prompt. [Shell policy](../../../../../clean-room/crates/execution/src/policy.rs#L189-L203)

A successful structured-writer spike should unblock only this owned uncapped INT-LOOP task. It does not authorize arbitrary paths, generic file editing, hidden holdout access, model-directed mounts, new services, modified credentials or router policy, production activation, or automatic promotion. The remaining design must earn a real candidate through one bounded attempt and independent evaluation; a green transport, a writer success status, or a clean teardown alone is not that result.

---

## disagreement-round-1.md

# Moderator synthesis — round 1

Root moderates using all three position papers and current evidence. All personas select A only for the bounded task and reject B/C. No major factual contradiction remains. The following proposals are offered for final adversarial response; maintain/concede explicitly and cite evidence, separating desired tests from existing results.

1. **Partial writes:** durable unknown-before-effect, permanent quarantine and verified teardown suffice for this scope; no atomic two-file transaction claim. Refusal after effects is also quarantined. Existing unknown fences remain immutable; continuous user authorization permits a reviewed new generation only after old roots are verified absent, without pretending it reconciles an old effect.
2. **Byte contract:** enforce per-file valid UTF-8 bytes and aggregate canonical serialized argument bytes before tool admission and at writer stdin; account for outer-frame headroom too. JSON Schema character limits are additional conservative hints and must not be represented as byte checks. Reject duplicate keys, invalid surrogates, NULs and overflows with no truncation.
3. **Import:** root has now implemented complete entry-set and baseline checks, generation source-path/device/inode/mode binding, regular single-link files and immutable hashes. Two local tests cover extras/changed baseline/hardlinks/wrong generation and accepted snapshot; actual revised NUC path remains to be exercised. Recheck committed blobs. Never mount evaluator authority or run candidate code on host.
4. **Wiring proof:** task-specific pinned MCP writer-only schema, trusted first request, strict full SSE/ID/name/argument binding, durable tool consume, fixed writer in precreated network-none executor; synthetic actual Goose positive and negative controls, crash points/owner loss/cleanup failure remain pre-live gates.
5. **Scope:** no generic file service, shell relaxation, model override, key/router mutation, production activation or promotion approval. Runtime integration still must earn every result.

Targeted questions: Is any major disagreement unresolved? Which exact minimal crash/cleanup controls discriminate quarantine from false success without imposing unrelated production fault proofs? Can the existing contained executor be used unchanged except for a fixed read-only writer mount, or does that create an unreviewed alternate authority? Which observed result would block a fresh live attempt?

---

## response-harness-round1.md

# Harness response — round 1

**Maintain A with the moderator's constraints.** I agree with security and operations that the specific task needs a two-file writer, not a broader shell or generic filesystem service. No major substantive disagreement remains. The remaining issue is evidentiary: the current writer and relay are unregistered fixtures, while the actual Goose worker and stream parser still select shell. Their unit results do not prove the proposed combined path. See the [shared ledger](evidence-ledger.md), [worker](../../../../../clean-room/tests/fixtures/nuc_goose_relay_worker.py), and [stream parser](../../../../../clean-room/tests/fixtures/nuc_bifrost_stream.py).

**Concede** that two-file atomic publication is unnecessary for this scoped run if every ambiguous or partial generation is quarantined and never evaluated. Also accept the moderator's aggregate serialized UTF-8 byte contract, independently checked before admission and at writer stdin. Schema character limits are hints, not byte enforcement. Duplicate keys, invalid surrogates, NUL, overflows and extra keys must fail without truncation. A refusal after effects is not a no-effect receipt. The existing [writer](../../../../../clean-room/tests/fixtures/nuc_factory_write_files.py) has separate links and best-effort cleanup, so it cannot establish atomicity.

**Executor authority remains a proposal, not a demonstrated fact.** An unchanged existing executor with a fixed, host-selected read-only writer mount is acceptable only if inspection and synthetic tests show that its fixed execution entrypoint invokes that exact writer directly, with no model-selected path, shell interpretation, network, or other authority. The current batch's `exec_once` contract and executor need review for that actual invocation; a mount alone does not establish it. If the entrypoint cannot invoke the writer without broadening its command interface, implement and review a separate fixed invocation rather than treating the mount as a capability grant. The [batch guardian](../../../../../clean-room/tests/fixtures/docker_batch_guardian.py) provides lifecycle machinery, not proof of this new dispatch.

The minimal synthetic end-to-end gate should use actual Goose with a task-specific pinned MCP schema, synthetic provider, trusted initial request and existing host gate. A positive case must assemble a complete valid stream, bind its sole tool ID and duplicate-free exact arguments, durably consume before effect, execute the fixed writer once, capture its actual result, and bind the continuation to the accepted first request and actual tool result. Check both file bytes and fixed response after verified teardown. Negative cases must show no writer effect for altered tool name, ID, arguments, initial system/user/schema, forged result, malformed or truncated stream, duplicate keys, invalid Unicode and frame or file limits. A replay or second tool call must not start another execution. The distinction matters because [RunFence](../../../../../clean-room/tests/fixtures/nuc_run_fence.py) records hashes and unknown stages; it does not itself validate the host-owned transcript.

For crash discrimination, test at least: death after durable consume but before writer start; death after first final link; lost writer acknowledgement after effects; and death or failure during result persistence or cleanup. Reopen the same fence and verify replay is denied, partial contents are retained as quarantined evidence, and no snapshot or success is released. Separately kill the supervised owner while roots are live and verify the recovery path removes both recorded roots and observes the same slice empty; inject a stop failure or missing receipt and verify release is withheld. These controls address the actual scoped failure windows without claiming host or daemon-loss recovery. The earlier independent brake evidence is useful but concerns the existing synthetic path, not this writer integration ([brake evidence](../../verification/2026-10-28-nuc-authenticated-batch-brake.md)).

A fresh live generation is blocked by any unverified prior root or slice cleanup, missing or reusable durable consume, mismatch between provider call and writer input, incomplete stream, unexpected executor authority, failed byte validation, partial or ambiguous result, or failure of the revised generation-bound import and isolated evaluation controls. Prior unknown fences stay immutable. Parent reports two local tests for the revised freeze checks; actual revised NUC execution is still required. A separate fresh generation after verified cleanup does not reconcile an earlier unknown and cannot establish production readiness or promotion approval.

---

## response-security-round1.md

# Application-security response — round 1

## Maintain and concede

I **maintain** the task-scoped typed writer recommendation and the existing shell-policy boundary. I **concede** that this experiment does not need an atomic two-file transaction if the integrated system proves that every incomplete or uncertain effect is quarantined and cannot be accepted, evaluated, imported, or automatically replayed. The [writer](../../../../../clean-room/tests/fixtures/nuc_factory_write_files.py) has sequential links and best-effort cleanup, so no stronger atomicity or rollback claim is justified. A later generation may be separately authorized under the continuing task instruction only after the prior owned roots are verified absent and slice admission is clear; it must retain the old unknown fence and candidate without claiming to reconcile them. I accept the moderator's revised import description as locally tested evidence, subject to actual NUC verification ([ledger](evidence-ledger.md)). There is no remaining major design disagreement among the three positions; there are material unresolved implementation and verification gates.

## Byte contract

I **maintain** per-file UTF-8 byte limits plus an aggregate bound; I **concede** the moderator's more precise formulation: calculate the canonical serialized arguments in UTF-8 after strict duplicate-free parsing, and enforce that same byte ceiling before tool admission and again at writer stdin. Independently check the actual serialized size of every enclosing provider, relay, MCP and executor frame against its own maximum. Outer headroom must include object names, escaping, IDs, JSON framing and newline; canonical size alone cannot prove a noncanonical outer frame fits. Reject before side effects if any applicable bound fails. Reject invalid surrogates, NUL, extra keys and nonempty-file violations; never silently truncate. Schema character limits are hints, not UTF-8 byte enforcement. The current separate file and frame limits are visible in the [writer](../../../../../clean-room/tests/fixtures/nuc_factory_write_files.py) and [relay](../../../../../clean-room/tests/fixtures/nuc_structured_file_relay.py).

The minimum falsifying controls are accepted boundary and first-rejected-byte cases for canonical and outer frames; a multibyte and an escape-heavy pair; malformed Unicode and duplicate keys; and evidence that rejected inputs cause zero writer invocations. This is a testable contract, not a claim that all arbitrary inputs at each individual file maximum fit simultaneously.

## Containment and negative proofs

The existing supervised executor may be reused with a fixed read-only writer mount only if the actual invocation is a distinct trusted, fixed argv for that writer, without shell interpretation or model-controlled executable, mounts or environment. A mount alone is not a dispatch design: current [`Batch.exec_once`](../../../../../clean-room/tests/fixtures/docker_batch_guardian.py) hardcodes `/execution --tool-request`, a shell-oriented executor path. Adding an arbitrary selector or retaining a worker-reachable alternate shell would create new authority. Review the exact fixed dispatch, mount set, network-none settings and one-use binding, and prove the advertised MCP capability exposes only the writer.

For a minimal crash and cleanup matrix, inject: (1) death after durable tool-unknown but before any write; (2) death after the first final link and before the second; (3) loss of acknowledgement after both writes but before durable result; and (4) stop or cleanup failure after writing. Each must leave no published result, snapshot, import or replay; preserve the old fence and require verified exact-root teardown before any new generation. Separately inject a writer refusal after an effect and a stale or missing teardown receipt, since neither is proof of rollback. Include a success control with both exact bytes, a complete durable result, clean teardown and hash-bound evaluation. These distinguish false acceptance from genuine completion without pretending to prove recovery from host or daemon compromise. Existing [fence code](../../../../../clean-room/tests/fixtures/nuc_run_fence.py) and [batch lifecycle](../../../../../clean-room/tests/fixtures/docker_batch_guardian.py) are components whose combined behavior still needs demonstration.

## Fresh-attempt blockers

Block a fresh live attempt if actual Goose cannot invoke only the pinned writer, a substituted tool/ID/argument or duplicate key reaches the writer, frame enforcement permits truncation or overflow, a partial/refused/unknown generation reaches evaluation, owner-loss cleanup fails to prove the recorded roots absent and slice empty, or a substituted generation, extra entry or changed baseline is accepted by the evaluator. A synthetic positive path and the above negative controls must pass together before the live path is considered. Successful fixture evidence remains distinct from production authority, migration, holdout provenance and independent recovery gates; human action-bound promotion remains separate.

---

## response-operations-round1.md

# Operations response, round 1

**Maintain** A for the single task, with durable unknown and quarantine rather than an atomic two-file claim. I agree with security and harness that the capability must be wired across the actual Goose advertisement, provider stream, host gate and owned executor; the helper alone is not an integration. I also accept the moderator's aggregate canonical UTF-8 argument limit and separate frame headroom, in addition to per-file limits. A schema character limit is only a hint; strict byte validation before `begin_tool` and again at writer stdin is authoritative. [Round 1 synthesis](disagreement-round-1.md)

**Update:** the exact-entry objection in my position paper was valid against the inspected prior version, but root has now added candidate generation binding, full directory enumeration and baseline checks. Current `freeze` binds the source path/device/inode/mode to the generation manifest and checks the complete entry set; local positive and negative tests have passed according to the moderator. [Current evaluator](../../../../../clean-room/tests/fixtures/nuc_int_loop_evaluator.py#L25-L60) This is implementation evidence, not proof of the revised NUC path. Preserve the post-stop empty-slice requirement and compare final committed blobs with evaluated hashes. [Task finalizer](../../../../../clean-room/tests/fixtures/nuc_int_loop_task.py#L19-L35)

There is no major unresolved design disagreement for the bounded task. I retain one operational distinction: a quarantine decision need not prove rollback. The writer's two links and best-effort unlink are not transactional, so refusal, crash, result loss, or failed cleanup can leave a pair that looks complete. [Writer](../../../../../clean-room/tests/fixtures/nuc_factory_write_files.py#L14-L35) The release gate must distinguish a complete-looking directory from a verified, durably recorded success. A separately reviewed new generation within the user's continuing authorization may follow verified owner teardown, but it never resets the older unknown fence or claims to determine that generation's effects.

## Minimal discriminating failure controls

Run these against the actual writer and supervised ownership path in a disposable synthetic fixture, with no live provider call:

1. **Positive control:** one valid provider-bound call writes exactly the specified bytes; its durable result, exact entry/baseline check, verified teardown and snapshot pass. A no-call control creates no output. This establishes the acceptance path can succeed.
2. **Partial-effect crash:** terminate the owned writer after the first final link and before the second, with a readiness handshake rather than timing alone. Confirm the durable fence remains `tool_unknown`, the exact roots are stopped, and neither import, evaluation, finalization nor replay succeeds. Preserve partial and hidden entries; do not clean them merely to make the test pass.
3. **Complete-looking but unacknowledged:** terminate after the second link but before the durable tool-result record, or drop the writer result before recording it. Even when both names contain correct bytes, the fence must remain unknown and downstream release and replay must fail. This is the critical false-success negative control.
4. **Cleanup uncertainty:** inject a refused or unresolved owned-root cleanup/empty-slice observation after an otherwise valid writer result. No snapshot or success receipt may be published. A separate positive cleanup control must confirm exact owned IDs are absent and the same slice is empty; never substitute a timeout or a removed directory for proof.
5. **File operation failure:** deterministically force a link or fsync failure after one effect, plus one failed temporary-file unlink. Assert refusal is quarantined, extra/link-count evidence survives, and exact-entry validation does not accept it. These concrete controls cover the fixture's relevant ambiguity without claiming host power-loss, daemon-loss or every production filesystem fault has been proven.

The exact existing `exec_once` cannot invoke this writer unchanged: it hardcodes `/execution --tool-request`, a command-oriented shim. [Batch guardian](../../../../../clean-room/tests/fixtures/docker_batch_guardian.py#L219-L235) Reuse its owned container and lifecycle only with a separate **fixed**, host-selected writer invocation and read-only pinned writer mount, bounded stdin/output, one-shot durable admission and the same stop fencing. Do not accept an executable, arguments, mount, path or shell command from the model. The new invocation is an additional authority and must receive its own end-to-end positive, substitution and replay tests; it should not be presented as a harmless mount change.

Any actual synthetic canary producing a write before the durable consume, accepting mismatched tool ID or bytes, releasing after any unknown above, overlooking extra files or a changed baseline, or failing to remove exact owned roots and observe the bound slice empty blocks a fresh live writer attempt. An unavailable or ambiguous test also blocks that claim. The prior authenticated two-root brake remains useful supporting fixture evidence, not a substitute for this writer-specific test or a production recovery claim. [Brake evidence](../../verification/2026-10-28-nuc-authenticated-batch-brake.md)

---

## consensus-plan.md

# Consensus: bounded structured task writer

Status: **CONSENSUS_REACHED**, three reviewers, one adversarial response round. Evidence is adequate for implementation and a synthetic spike, not production activation. Root moderated because a specialized moderator type is unavailable. All research used current primary local code and dated actual NUC observations; no new vendor/current-release recommendation was made.

Choose A: only `factory__write_files`, exactly `hello.py` and `test_hello.py`, in the task-specific protected Goose MCP configuration. No shell-filter relaxation, encoded-source shell workaround or generic filesystem API. The existing Bifrost auto router, factory key and shared services remain unchanged. The user-waived monetary cap stays waived for this named run.

## Required implementation and release contract

1. One strict shared argument contract: exact keys/names, valid nonempty UTF-8, no NUL, per-file byte bound and aggregate canonical JSON byte bound. Separately enforce every real outer frame bound; schema character limits are hints, not byte enforcement. Duplicate keys/invalid Unicode/overflow reject without truncation or effects.
2. Pin the writer-only MCP schema and trusted task initial request; validate complete stable-identity SSE and exact tool name/ID/arguments. Durable consume precedes effects. Continuation uses only host-owned request, validated provider assistant and captured actual writer response. Worker-supplied results, altered transcript, second/replayed calls cannot dispatch.
3. Reuse the owned network-none/cap-dropped executor lifecycle only with a distinct fixed writer argv and read-only factory writer mount. Model input cannot choose a program, path, mount, option, environment or shell. Shell and writer paths must not become alternate unreviewed deputies.
4. The pair is not atomic. Interrupted, refused-after-effect, malformed, timed-out, acknowledgement-lost or cleanup-uncertain outcomes remain durably unknown/quarantined and cannot be imported/evaluated/promoted or retried in place. Preserve evidence rather than deleting remnants to make a check pass. Existing unknown attempts are immutable. Continuing authorization permits a reviewed new generation only after prior exact-root teardown and empty slice, without claiming old-effect reconciliation.
5. Before snapshot, verify successful generation/fence, stop both exact owned roots, check same slice empty, bind candidate path/device/inode to generation, require exact baseline README plus two outputs, unchanged baseline, regular single-link bounded files and no hidden extras. Freeze privately; challenges execute in owned read-only network-none containers with no holdout helper, credentials, sockets or Git authority. Compare actual committed blobs with evaluated hashes. Promotion requires separate action-bound human approval.

## Discriminating pre-live proof

- Actual Linux Goose/MCP → strict provider/service/fence → fixed isolated writer positive control, exact bytes/status/continuation, no-call and substituted tool/name/ID/content controls.
- Byte/outer-frame boundaries, escape-heavy and multibyte content, malformed Unicode/duplicates, traversal/extra names, existing/symlink/hardlink files, replay/concurrency/restart controls.
- Crash after durable consume before effect; after first link; complete-looking files with lost acknowledgement before durable result; refused-after-effect/fsync/unlink failure; cleanup/receipt failure. Each withholds snapshot/import/replay and preserves quarantine. A verified success control must advance.
- Actual writer owner-loss recovery removes both exact roots and observes same slice empty. Existing brake proof is supporting evidence, not a substitute for writer-specific ownership.
- Revised generation/entry-set/baseline freeze and isolated evaluator controls pass against actual output before any candidate claim.

No unresolved major design disagreement or new human decision remains for this scoped implementation. These tests are outstanding work, not results created by consensus. Production journal/identity/migration/holdout/recovery and complete phases 11–14 remain separately required; no production or project completion follows from the debate.
