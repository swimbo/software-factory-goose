# Operations position: prefer private admin and retire ungated execution

## Conditional direction

Prefer **per-service Unix-only admin, a fixed root-mediated administrative
channel, and retirement of all ungated SDK1–4 execution endpoints**, conditional
on one bounded disposable test with the exact installed Restate1.8.0 binary.
This direction replaces an exposed administrative surface and removes obsolete
execution paths. It avoids making normal safety depend indefinitely on a
socket-UID firewall rule whose coverage includes inherited connections,
address families and namespace recreation.

Evidence is adequate for this conditional preference, not production adoption.
If the exact binary cannot expose admin separately with usable protected
permissions, stop this direction and reconsider the scoped nftables alternative
from the resulting evidence. Do not perform a live Restate restart just to find
out. The root administrator, Docker daemon, PID1, trusted SDK code and Restate
UID2004 remain in the stated trust boundary; this is not resistance to their
compromise. Accidental socket inheritance still needs testing.

## Why this is the smaller operational boundary

The pinned source contains Unix/TCP listener modes and per-service admin options,
so the Unix route is a concrete candidate, not speculative new infrastructure.
The installed binary's help confirms those modes, while its default-config dump
does not establish effective Unix socket permissions. That last question is
small enough to answer directly. [Pinned common configuration](https://github.com/restatedev/restate/blob/v1.8.0/crates/types/src/config/common.rs),
[pinned admin configuration](https://github.com/restatedev/restate/blob/v1.8.0/crates/types/src/config/admin.rs),
[networking documentation](https://docs.restate.dev/server/networking),
[Linux research](linux-research.md).

The mediated channel must expose only reviewed operations: exact deployment
registration and fixed drain/history queries bound to a root plan. It must not
accept arbitrary SQL, URLs or HTTP bodies. Prefer reusing the trusted journal
role and existing root peer-checking pattern over adding a new permanent
privileged network daemon. Whether its process can remain capability-empty
depends on the actual socket path and mode. A root-owned program serving a
root-authenticated operation is the requirement; blindly making a private data
directory searchable or granting broad capabilities is not an acceptable
shortcut. Native permission proof should settle the smallest usable arrangement.

Self-hosted Restate deliberately relies on external protection for admin access.
Leaving9070 generally available to SDKUID2000 is not a temporary convenience
once that role can change registrations behind the transition gate. Existing
registration and inspection scripts must move to the mediated path in the same
acceptance slice. [Restate server security](https://docs.restate.dev/server/security),
[durable research](durable-research.md).

## The8080 route must be closed as an execution path

I maintain the forwarding objection from my research. Denying UID2000 to9070
and old SDK ports while allowing8080 and RestateUID2004 to old SDKs still lets
UID2000 submit mutations through Restate. The dispatcher changes the network
origin, not the application's authority. That route must be included in the
positive control; a failed direct-port connection is insufficient evidence.
[Restate ingress semantics](https://docs.restate.dev/server/security),
[operations research](ops-research.md).

Retiring every ungated SDK execution endpoint closes that dispatch target even
when a request was already accepted or pinned. Cover SDK1,2,3 and4, not merely
the latest active catalog. Preserve their binaries, exact deployment records,
unit definitions, journal history and reservations. Prove each process and
listener terminal, cgroup empty, no pending manager job and no surviving
descriptor owner that can serve the endpoint. Fence sockets and dependency
activation as well as services. Locally installed unit files make a simple
`systemctl mask` assumption unsafe: systemd documents that an existing local
unit at the mask path can prevent masking. Use a reviewed exact backup and
replacement protocol; runtime-only fencing does not survive reboot.
[systemctl257](https://www.freedesktop.org/software/systemd/man/257/systemctl.html),
[systemd.kill257](https://www.freedesktop.org/software/systemd/man/257/systemd.kill.html).

## Retained work is not drained work

Stopping an endpoint does not complete its old-pinned invocations. Restate's
versioning model preserves the original endpoint association. Therefore permit
release only with either a tested zero predicate after effective fencing, or
explicitly enumerated, immutable quarantine records for retained nonterminal
work whose old execution endpoints cannot restart. Call the latter unavailable
and quarantined, never quiescent, drained or migrated. Do not cancel, delete,
force-register or restart-as-new merely to obtain zero. Cancellation itself
requires observed terminal state and effect reconciliation.
[Restate versioning](https://docs.restate.dev/services/versioning),
[invocation management](https://docs.restate.dev/services/invocation/managing-invocations).

Unpinned and scheduled work must be classified too. A request accepted just
before fencing may become visible later; stopping all old code prevents its
execution but does not prove it never existed. The new gated runtime must not
reinterpret those records as fresh claims. The exact pinned-binary control
should establish the queried states and how SDK5 registration affects them,
using the real server-minted deployment IDs rather than fabricated table rows.
[Pinned queue-metadata release note](https://github.com/restatedev/restate/blob/v1.8.0/release-notes/v1.7.4.md).

## One bounded spike and four live gates

Run one disposable fixture with a fresh state directory, exact1.8.0 executable,
synthetic old/new SDKs and no credentials. Establish completed history plus one
controlled in-flight, one queued and one scheduled/unpinned request. First show
the8080 forwarding bypass. Then prove Unix-only admin denies TCP9070 and
UID2000 direct socket access, while the fixed mediated operation works. Retire
the old endpoint, register the new one once without force, inspect the real
pending rows and prove no old counter mutation occurs through direct, reused
or forwarded connections. Restart only the disposable Restate and show the
same restrictions and retained history persist. Kill the fixture controller
around retirement and registration to test closed recovery. This is enough
to choose the implementation direction; a huge generalized firewall framework
is not required.

Before a separately reviewed live transition, require four concrete gates:

1. Exact owned backups and a durable closed transition marker precede any
   endpoint/configuration change; shared Docker, Bifrost, Hermes, Stapled,
   PostgreSQL and their data remain untouched.
2. The new admin boundary and permanent SDK1–4 retirement are established and
   rechecked before consuming drain/quarantine observations.
3. One non-force registration is bound to its actual response or retained as
   unknown; fresh service/socket attestation and every retained history replay
   pass before admission reopens.
4. Private Restate restart or namespace recreation cannot reopen old SDKs or
   TCPadmin through defaults. Missing boundary, lost acknowledgement or any
   uncertain effect retains the closed marker and requires exact recovery.

These gates preserve the factory's own durable data while allowing a deliberate
owned-service transition. They do not authorize shared-service restarts, new
model work, candidate promotion or erasure of older attempts.
