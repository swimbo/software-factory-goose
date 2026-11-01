# Registry ingress fence: evidence ledger

User approved three reviewers on 2026-10-30: Linux networking, durable runtime,
and contrarian operations. Research precedes positions. No production choice,
network policy change or service restart follows from this ledger.

| Fact or inference | Evidence | Decision consequence |
| --- | --- | --- |
| Self-hosted management interfaces require external access controls; request identity is a different direction of authentication | [Restate security](https://docs.restate.dev/server/security), fetched 2026-10-30; three research briefs | A Root wrapper alone cannot protect directly reachable admin TCP |
| Installed pinned binary reports 1.8.0 and supports Unix/TCP/all; exact configured behavior remains untested | Read-only installed binary help; [durable research](durable-research.md) | Test this binary, rather than infer socket modes from current docs |
| Fresh explicit empty-environment dump emits admin section but omits optional listener values | `/tmp/sfactory-restate-1.8-default-config.toml` on the Mac; command reads installed NUC binary with `env -i` and `--dump-config` | Does not establish Unix activation, permission, precedence or effective live configuration |
| SDK1–4 are active UID2000 in the private namespace; SDK5 is installed inactive | Fixed unit inventory in [brief](brief.md) and [Linux research](linux-research.md) | Retirement must cover every ungated old endpoint, not SDK4 alone |
| New journal handlers and Root grant callers take the registry gate; older installed binaries do not | Current source plus installed-version reconciliation | An exclusive lock cannot fence old code which never takes it |
| Leaving 8080 available lets a caller ask trusted Restate to dispatch to an old SDK | [operations research](ops-research.md), inference from ingress/worker routing | A direct-port UID filter alone is incomplete; test this forwarding route |
| Socket UID differs from the process currently using a transferred descriptor | Linux/nft primary citations in [Linux research](linux-research.md) | Test existing connections and accidental descriptor transfer; trusted Root/UID2004 compromise remains outside the boundary |
| Invocation and queue deployment columns exist on the installed server | Native schema receipt `/tmp/sfactory-identity-admin-8mdevoh2` | Schema presence does not establish a drain predicate or stop future admission |
| Stopping an endpoint can leave old pinned work unavailable | Restate deployment semantics and [durable research](durable-research.md) | Preserve and classify work; unavailable is not completed or drained |

Research artifacts: [Linux](linux-research.md), [durable runtime](durable-research.md),
[operations](ops-research.md). Primary URLs and current-versus-pinned limitations
are captured there. The next position round must select the smallest decisive
disposable experiment and state the conditions for any later real transition.

## Registration force semantics, pinned Restate 1.8.0

The [v1.8.0 request model](https://github.com/restatedev/restate/blob/v1.8.0/crates/admin-rest-model/src/deployments.rs#L141-L200) declares `force` in the registration JSON body. The [v1.8.0 handler](https://github.com/restatedev/restate/blob/v1.8.0/crates/admin/src/rest_api/deployments.rs#L70-L91) uses an omitted value as true on API V1/V2 and false for other versions; the [router](https://github.com/restatedev/restate/blob/v1.8.0/crates/admin/src/service.rs#L186-L209) assigns the unprefixed `/deployments` path `AdminApiVersion::Unknown`. Therefore the existing fixed unprefixed URI-only call on this pinned binary takes the non-force branch. That source conclusion is distinct from independently proving the attempted URI was fresh or that no prior same-URI registration was retried. Preserve prior installed helpers and retained receipts; future versioned fixed helpers must explicitly send JSON `force:false` and `breaking:false` and retain the one-attempt/unknown fence. Do not infer force behavior for other server versions or routed paths from this check.
