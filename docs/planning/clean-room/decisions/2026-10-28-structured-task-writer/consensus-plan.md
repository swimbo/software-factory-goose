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
