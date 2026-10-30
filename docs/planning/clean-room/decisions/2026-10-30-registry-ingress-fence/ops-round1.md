# Operations round1: agree with the bounded Unix candidate

I agree with all four resolutions in [moderator-round1.md](moderator-round1.md).
No remaining operations objection blocks the proposed experiment. The result
will select a conditional direction; it will not certify a live transition.

## 1. Demonstrate the route, then prove execution retirement

I maintain that the8080 forwarding route needs a falsifiable positive control.
It is sufficient to show a same-UID caller changes an old SDK's synthetic
counter through Restate8080, then show that permanent endpoint retirement
prevents further direct and forwarded effects, including existing connections.
I explicitly concede any interpretation that requires installing hypothetical
nft rules to demonstrate that fact. The chosen Unix candidate does not depend
on those rules, so testing a separate firewall would add work without settling
its acceptance boundary. Self-hosted Restate's distinct invocation and admin
surfaces explain why this control matters. [Restate server security](https://docs.restate.dev/server/security).

For later live application, cover every ungated SDK1–4 endpoint, its listener,
socket activation path and exact process cgroup. A failed fresh connection
alone does not establish that no accepted connection can still execute old
code. Preserve unit definitions and use restart fencing that survives the
intended owned restart; systemd documents the limitations of masking locally
installed units and runtime masks. [systemctl257](https://www.freedesktop.org/software/systemd/man/257/systemctl.html).

## 2. Trusted UID2004 may perform the fixed admin operation

I agree that PID1 may execute fixed Root-owned administrative code as the
already trusted journalUID2004. This is Root-mediated administration because
Root selects and authorizes the exact operation; it is not a claim that the
server sees UID0. Keep the private data tree and Unix socket permissions strict.
Do not add groups, firewall privileges, generic shells or arbitrary SQL/URL/body
arguments merely to preserve a cosmetic UID0 label.

Require exact Root-owned program/configuration hashes, fixed namespace and
operation, bounded pipe responses and durable Root receipts. Do not pass an
administrative connection or descriptor to SDKUID2000. Root, PID1, daemon and
journalUID2004 remain trusted; accidental inherited or transferred descriptors
remain a real test condition. The pinned source supports per-service listener
options, but only the actual fixture establishes usable socket permissions.
[Restate1.8.0 admin options](https://github.com/restatedev/restate/blob/v1.8.0/crates/types/src/config/admin.rs),
[Linux unix(7)](https://man7.org/linux/man-pages/man7/unix.7.html).

## 3. One owned fixture is sufficient for this decision

I agree to the fresh factory-owned namespace/data root, exact installed binary,
two synthetic SDKs and disposable role probes. Test actual Unix path/mode/ACL,
TCPadmin absence, UID2000 denial, fixed UID2004-mediated operation, direct and
forwarded old effects before/after retirement, pinned/queued classification,
one registration with lost response and an owned restart. Clean up only exact
owned resources after terminal proof. A host reboot or destruction of the live
namespace would be disproportionate and is outside this spike. Those live
persistence claims remain later gates rather than silently passing.

## 4. Retained quarantine remains distinct from completion

I maintain the durable closed Root intent, recoverable backup, preserved
deployment histories, permanent old-endpoint retirement and fresh SDK5
attestation/registration/history replay requirements. A retained old invocation
that cannot execute is unavailable quarantine, not drained work. Its scope
must remain closed if its effect is uncertain; this agreement does not invent
an unimplemented partition that permits unrelated admission.

Restate's original deployment association explains why stopping an endpoint
does not migrate its pending work. Unknown registration must be reconciled
without another POST, and cancellation acknowledgement cannot substitute for
terminal/effect evidence. No silent cancellation, history deletion, force
registration or reopening follows from this experiment. [Restate versioning](https://docs.restate.dev/services/versioning),
[invocation management](https://docs.restate.dev/services/invocation/managing-invocations).
