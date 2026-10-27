# G05 bounded durable promotion execution — 2026-10-27

Status: local implementation and disposable runtime evidence; unregistered production service. This does not close G05 activation, authoritative task ownership, distinct-UID provisioning, or the independent-stop gate.

## Contract

`PromotionDecisionJournal::execute` accepts only a nonce. It resolves the current consumed approval/decision from the same durable object, checks its generation, exact action/evidence, operator, audience, and consumption timestamp, then resolves filesystem paths from an explicitly configured registry. Prepared and Completed state contain the exact action, generation, mapping fingerprint and intent. A Prepared record means unresolved execution, not successful promotion.

A new attempt durably stores Prepared before its journaled side effect. The local bare repository then receives a create-once, fsynced per-branch fence containing the bound intent. Only creation of that marker permits a fresh exact-base Git CAS. The same intent permits read-only reconciliation, even after process replay; a different task, nonce or generation cannot acquire the existing branch fence. A crash after marker creation but before CAS deliberately sacrifices availability: a target still at base is refused, rather than retried. The fence has no reset/delete API and is never automatically cleared, including after known success. This bounded implementation therefore admits only one fresh mutation per branch until a separately verified recovery design exists.

If the exact target already equals the candidate and ancestry matches, the receipt says `ReconciledAlreadyAtCandidate` and `attribution_unknown: true`. It cannot identify which actor moved the ref. An observed successful own CAS produces `Advanced`; Completed retries return the historical receipt and do not repeat Git mutation. Neither receipt guarantees that a later external actor has left the branch unchanged.

Invalidation and changed generations refuse execution even when Prepared exists. Retained Prepared history also quarantines all new eligibility publication in that task object, including after invalidation, so a new generation/nonce cannot bypass an unknown outcome. This is atomic with this object's own eligibility state, not an external ClaimLeaseJournal snapshot. No claim is made that cancelling an in-flight handler retracts an OS side effect already in progress; independent stop/fencing and all authoritative eligibility writers still require deployment integration.

## Filesystem and subprocess boundary

`TrustedPromotionRepositories` takes operator-provisioned configuration, not deserialized client paths. It pins canonical roots/inodes and rejects symlink paths, unsafe ownership/mode/ACL, hard-linked files, special files, oversized trees/files, replaced roots, unsupported Git config, linked worktrees and alternate/shared object-store indirection. Only an exact direct branch in an exact bare Git root is eligible. Repository/candidate roots must currently be owned by the executor UID and mode 0700; this fixture policy does not establish separate operator-owned repository access or deployed UID isolation. The owner and root are trusted; concurrent hostile same-UID filesystem replacement is outside the proved boundary.

Git uses a fixed executable, cleared environment, disabled hooks/transports/external diffs, nonblocking bounded pipes, 8 MiB input/output caps, five seconds per command and a 30-second total Git promotion budget. Timeout/overflow kills the owned process group before bounded reap. `waitid(WNOWAIT)` retains the leader's PID until signaling, preventing the prior reap-then-signal ownership race. Cleanup failure returns an unresolved result; there is no automatic second CAS. This is not a hard memory limit or proof of handling every kernel-stalled process.

On macOS, signaling a zombie-only group may return EPERM: XNU filters zombies during group iteration and returns EPERM if no signalable members remain. The runner accepts this case only after a positive complete libproc enumeration contains exactly the known unreaped leader. Empty/error/truncated/other-member results refuse; inaccessible state is never treated as empty. [Apple XNU implementation](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_sig.c). The same ownership-fenced cleanup now protects the evaluator's Seatbelt subprocess runner. Unsupported process-ownership platforms fail closed; ACL validation is currently macOS-only.

## Verification

- Six real temporary Git/filesystem tests: exact CAS and lost-receipt recovery without a second ref write; marker-before-CAS interruption refusal; stale base/dirty source/unregistered repo/ref refusal; owner/mode/symlink/replaced inode refusal; pre-existing candidate recorded as unattributed observation; changed intent/hardlink/alternate object-store refusal. The alternates test failed before the Git-indirection check was added.
- Nine same-object decision tests, including refusal before consumption and after Prepared invalidation, changed generation, changed evidence, missing consumption, or changed operator. The execution-state test failed before the new guard and states existed.
- Two real subprocess tests: stalled input timeout, output overflow, successful bidirectional I/O, and exited leader with live descendant cleanup. The initial positive I/O test exposed Darwin's zombie-only EPERM case; the narrowly checked libproc handling resolved it.
- Evaluator `exact_revision` integration: 9/9, including actual isolated build/test verdicts, host/network denial, dirty/changed/nonbare refusal, explicit target and symbolic-ref protection.
- Strict Clippy passed for evaluator/control-plane libraries and the synthetic SDK fixture. Python fixture syntax and whitespace checks passed.

The disposable native Restate/PostgreSQL fixture provisions two fresh local Git repositories with synthetic commits; it never clones or writes a user repository. It verifies actual publish/issue/consume/execute, discarded execution reply, durable Completed receipt, no second ref write on retry, client path/action rejection, dirty-source failure persisting Prepared, restored-clean retry refusal, and invalidation refusal. Restate SIGKILL/restart preserves the successful receipt and the invalidated Prepared refusal. This kills Restate after the execution has completed; it is not proof of a crash at every internal Git instruction. The unit marker interruption test covers the conservative before-CAS replay rule.

The fixture preserves the existing real Unix worker/approval backend checks, lost consume reply, queue/budget replay, graceful restart and SIGKILL tests. All services remain synthetic and loopback-only. Configured fixture principals and same-account sockets are not production authentication or cross-UID proof.

## Remaining gates

- Authenticate the private ingress and restrict source, operator, generator and admin roles.
- Make the real task-state owner route all eligibility publication/invalidation through the authoritative decision owner.
- Provision and verify distinct identities, trusted repository mapping/access and independent stop behavior.
- Exercise approved deployment failure windows, including interruption during an actual external action; reconcile without assuming the Restate/Git boundary is a transaction.
- Do not activate this service through a bare `main.bind` change. Production main remains unchanged.


## Adversarial follow-up

Three concrete replay defects were reproduced and fixed:

1. A forged deserialized low-level intent with a budget operation could reach Git because only `prepare` required Promote. Both execution/reconciliation now recheck Promote and distinct base/candidate; low-level methods are crate-only. The negative test previously moved a disposable branch and now refuses before creating a fence.
2. Republishing eligibility after unresolved Prepared could acquire a new generation/nonce and retry. New publication is now quarantined by any retained Prepared history; invalidation and historical exact request retries remain available. The fixture checks publication refusal before and after invalidation and Restate restart.
3. A different task object could bypass the old per-nonce external marker. Fencing is now per physical repository and configured branch. Atomic create-new admits one process; full intent comparison rejects another task/nonce. It survives actual child-process SIGKILL after fence creation and before CAS. Two concurrent task attempts admit exactly one fresh update, and a later valid candidate from another task/generation remains refused. Legacy nonce-named records or unknown fence-directory entries refuse upgrade rather than being silently treated as no fence. The relevant tests failed before these fixes.

A dropped queued blocking attempt now cancels its queued work and checks a cancellation flag before starting. A saturated single-thread blocking-pool test proves it never starts when capacity later frees, while the positive control executes. This is **not** cancellation of blocking work already running. The SDK invocation/independent-stop boundary must still prove that such work cannot outlive revocation; the current implementation does not establish that proof.

Branch fence filenames use a hash of the ASCII case-folded configured reference, conservatively sharing a fence for case-only names on case-insensitive macOS storage. Non-ASCII configured references fail closed instead of guessing Unicode normalization. Fence content retains task/generation/nonce/action and mapping fingerprint for inspection, without exposing filesystem paths.

### Recovery boundary and unsolved attacks

There is deliberately no supported recovery/delete command. Do not infer that an old timestamp, expired approval, Restate cancellation, exited SDK, or current Git SHA proves no prior OS action remains. A future recovery procedure must establish that every prior executor/process is stopped, inspect the exact protected repository/ref and retained intent, reconcile task state with Git without claiming attribution from SHA alone, and reverify evidence/authority before enabling another mutation. Clearing or restoring a fence while an old action can run would defeat this protection.

The filesystem checks assume the executor owner and root are trusted. A hostile process with that same UID can swap directory contents between checks, alter/remove fence files, or replace Git metadata; descriptor checks and permissions do not make all subsequent path-based Git operations atomic. Cross-UID deployment protection remains unproved. Independent rollback/restoration of Restate state, Git and fence files also needs a coherent recovery design. Per-ref fencing prevents another fresh authorized attempt; it does not stop an already-running action, provide a Git/Restate transaction, or prove the independent brake.

Final follow-up verification: 24/24 promotion-filter tests passed (11 decision, 10 real Git/filesystem executor, three existing gate tests); strict control-plane/SDK-fixture Clippy passed; rebuilt native Restate/PostgreSQL fixture passed all seven reported checks, including new-generation publication refusal before/after invalidation and SIGKILL restart. No production registration or real user-repository mutation occurred.
