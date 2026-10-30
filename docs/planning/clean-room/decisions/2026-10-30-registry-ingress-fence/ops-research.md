# Operations research: registry ingress fence

Research only, 2026-10-30. No host, network, service or journal mutation.
Evidence is adequate to reject a count-only fence; insufficient to choose and
activate a live enforcement mechanism before the disposable spike.

## Facts and sources

1. The brief records Restate1.8.0 and four older active SDK processes in the
   factory private namespace. The schema canary establishes available columns,
   not absence of pending work or exclusivity. Repository sources
   `nuc_registry_drain_probe.py` and `nuc_registry_transition_gate.py` explicitly
   retain that distinction. These current observations were supplied in the
   [brief](brief.md); I did not repeat live NUC inspection.
2. Self-hosted Restate separates ingress, admin and fabric. Its admin interface
   has no application authentication; deployment registration and inspection
   therefore need an external access boundary. Ingress8080 accepts handler
   invocations, while admin9070 controls deployments. Source, accessed2026-10-30:
   [Restate server security](https://docs.restate.dev/server/security).
3. Pinned1.8.0 source contains `ListenMode::{Unix,Tcp,All}` and per-service
   listener options. Admin options embed those options and merge common
   defaults. Unix admin is technically credible on this version, but socket
   mode, namespace exposure, CLI precedence and restart/recovery still need
   actual tests. Sources: [v1.8.0 common.rs](https://github.com/restatedev/restate/blob/v1.8.0/crates/types/src/config/common.rs),
   [admin.rs](https://github.com/restatedev/restate/blob/v1.8.0/crates/types/src/config/admin.rs),
   [current networking docs](https://docs.restate.dev/server/networking).
   Pinned source was fetched directly; current docs alone would not prove1.8.0.
4. Restate's versioning model keeps invocation retries associated with their
   original immutable endpoint. Stopping an old SDK does not migrate those
   invocations to SDK5. Cancellation is asynchronous and is not evidence that
   effects were undone. Sources: [versioning](https://docs.restate.dev/services/versioning),
   [managing invocations](https://docs.restate.dev/services/invocation/managing-invocations),
   accessed2026-10-30. No publication date displayed.
5. Pinned release notes describe deployment metadata preservation for queued,
   scheduled and inboxed work, including the relevant introspection tables.
   This supports testing those states, not treating one SQL zero as proof of
   no future dispatch. Source: [v1.7.4 notes in the1.8.0 tree](https://github.com/restatedev/restate/blob/v1.8.0/release-notes/v1.7.4.md).
6. nftables `skuid` describes the originating socket UID. Base-chain priorities
   determine evaluation order; an accept can be followed by another chain,
   whereas drop terminates processing. Thus inherited sockets and pre-existing
   connections need explicit controls and tests. Sources, accessed2026-10-30:
   [packet metadata](https://wiki.nftables.org/wiki-nftables/index.php/Matching_packet_metainformation),
   [chain configuration](https://wiki.nftables.org/wiki-nftables/index.php/Configuring_chains).
7. systemd257 distinguishes disable from mask. Mask blocks activation but may
   fail for locally installed units already occupying its target path; runtime
   masks disappear on reboot. Unit stop normally kills the unit cgroup, subject
   to its actual KillMode and stop settings. Sources: [systemctl257](https://www.freedesktop.org/software/systemd/man/257/systemctl.html),
   [systemd.kill257](https://www.freedesktop.org/software/systemd/man/257/systemd.kill.html).
   Preserve local definitions before any separately reviewed retirement.

## Important inference: the proposed UID rule is not the whole fence

Option2 currently denies UID2000 direct access to9070 and old SDK ports but
leaves8080 available and permits RestateUID2004 to reach old SDKs. From facts2
and4, a UID2000 caller can still submit a mutating invocation through8080; the
dispatcher reaches ungated SDK4 as UID2004. This is an inferred bypass of the
proposed transition boundary, not a live exploit test. The spike must reproduce
and then close it. Do not claim admin/direct-port denial alone fences mutation.

Possible resolutions include temporary fencing/mediation of old invocation
producers at8080, or permanently stopping all ungated execution endpoints while
retaining their records. The latter blocks execution, but leaves residual pinned
invocations unavailable rather than drained. Both require an explicit protocol
for requests already accepted or queued before the fence.

## Option matrix: operational questions, not a final position

| Option | Operational attraction | Conditions and unresolved cost |
| --- | --- | --- |
| Retire every ungated SDK, retain immutable deployments/data, fixed root admin channel | Smaller future execution surface; normal SDK5 operations can remain gate-aware | Prove exact terminal processes/listeners/jobs and permanent restart fencing; preserve locally installed unit definitions. Existing pinned work may remain blocked and must be reported, not deleted or silently rerouted |
| Namespace-local nft policy plus fixed root admin broker | Could keep old handlers reachable only for controlled drain without restarting Restate | Must also close the8080 invocation route during transition; prove existing connections, passed sockets, all address families, other UIDs and boot persistence. Replace every legitimate UID2000 admin client before applying policy |
| Unix-only admin plus root proxy | Filesystem permissions offer a directly inspectable admin boundary without socket-UID firewall rules | Requires owned Restate restart, exact1.8.0 socket/config proof and replacement clients; old direct SDK/ingress routes still need fencing |
| Gate marker plus zero counts only | Minimal changes | Does not constrain older code or prevent new requests; reject as an enforcement mechanism |

Do not introduce a general privileged network daemon or arbitrary SQL/registration
proxy merely to complete one transition. A fixed root operation set is simpler
to audit and recover. Conversely, avoiding a small root broker is not a reason
to leave administrative mutation available to every SDK process.

## Unknowns that matter

- Complete client/descriptor and listener inventory is missing. A port list or
  source search does not prove there are no passed privileged sockets.
- Counts need positive controls for accepted, scheduled, suspended, backing-off,
  queued and unpinned work. A canceled request must be observed terminal; a
  returned cancellation HTTP status is not that observation.
- Need exact restart-fence behavior for the locally installed old services and
  sockets, including dependency activation, reboot and namespace recreation.
- Need an operator recovery path after losing the policy-install acknowledgement,
  dying between fence and registration, or registering SDK5 but losing its reply.
  The existing transition marker must remain closed; arbitrary marker deletion
  or restoring an ungated endpoint after new admission is not recovery.

## Smallest decisive spike

Create an isolated namespace with the pinned Restate binary, two tiny SDK
versions, synthetic UIDs and three test endpoints; no shared services or data.
One SDK handler must append a visible synthetic counter, and another must hold
a request across a barrier. First prove that the proposed admin/direct-port
rule still permits mutation through8080. Then compare an expanded ingress fence
with permanent old-SDK retirement. Exercise fresh and established connections,
passed sockets, IPv4/IPv6, an unrelated pre-existing chain and benign traffic.

Queue old-pinned and unpinned invocations before fencing. Verify exactly which
can execute, remain pending, or become terminal, and that SDK5 registration does
not revive old code. Kill the controller at each stage and recover using only
the recorded namespace, owned table, exact unit/process and server-minted
deployment identities. Success requires both falsifiable mutation denial and
an honest retained-work status. Remove only the owned fixture table/namespace
after known terminal cleanup. No live adoption recommendation until these
tests settle the enforcement and recovery gaps.
