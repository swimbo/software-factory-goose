# Okayr integration — addendum

How the homegrown task-management system ([`swimbo/okayr`](https://github.com/swimbo/okayr), a Rust
CLI/TUI over the existing Dev Projects / Hermes goal cascade + execution state) fits the
clean-room software factory. This is a **shape + identity-alignment note**, not a build order;
it extends `next-steps.md`.

## Summary

Integrate **at the identity boundary, not by merging engines.** The factory's work packages
should reference **native slice identities** (the user's real work) instead of synthetic
`scaffold → implement → test`, and **Okayr should be the factory's operator surface** — the
planning, observability, and approval window the factory's plan explicitly deferred.

## What Okayr is

- Rust `okayr` (CLI/TUI) + `okayr-server` (loopback `/v1` HTTP) + a Python adapter, over the
  **existing** NUC Dev Projects state. **No new database, no new entities.**
- Reads/edits the goal cascade: **Project → root goal → annual OKR → quarterly OKR → epic →
  slice** (slices have dependencies).
- Reads execution state: **claims/attempts, stage, lease, `executor_unknown`, receipts** bound
  to git revisions, plus planning decisions and `needs_direction` attention gates.
- Hard boundaries: **read-only on execution**, "a successful save never grants execution
  approval", single authority, no shadow records.

## Why this is a strong fit

1. **Same model.** The dark-factory report already names the factory's clean-room design as
   "the user's own Dev Projects factory (goal cascade + receipt-bound durable state)". The two
   share goals → cascades → claims → leases → stages → receipts.
2. **Okayr is the factory's missing operator surface.** The factory deferred a dashboard;
   Okayr already renders the hierarchy, stages, leases, receipts, and approvals. It is the
   "lights off, nothing unseen" view.
3. **Prevents a shadow system.** The factory's current `Task` (`scaffold/implement/test`) is a
   synthetic placeholder; the real work is slices. Keeping a parallel model is exactly the
   "shadow task / shadow execution records" divergence Okayr's plan forbids.

## The boundary that matters

Both systems own *claims/leases/stages/receipts*:

| Concern | Owner |
|---------|-------|
| Planning hierarchy (goals→OKRs→epics→slices) | Dev Projects (Okayr reads + edits via native owners) |
| Planning approval | Dev Projects (Okayr exposes; never fabricates) |
| Execution state (claims/leases/receipts) | **to be decided** — see ownership, below |
| Code production (build → wall → merge) | the factory |

Okayr is **read-only on execution**, so the factory cannot simply write into `state.json`; that
requires extending the native execution owner.

## Recommended shape

```
factory (execution engine)
   ├─ consumes native slices (via Okayr's read API or the native files)
   ├─ work packages carry native (project, epic, slice) identity
   ├─ produces receipts bound to git revisions
   └─ execution state is *read-only rendered* by Okayr

okayr (operator surface)
   ├─ planning edits + approvals (native owners)
   ├─ renders the cascade + execution state (stage/lease/receipt)
   └─ never mutates execution
```

## Identity alignment (the concrete change)

Give the factory's `Task` a native reference instead of a synthetic subject:

```rust
// shared/src/lib.rs — add
pub struct NativeRef {
    pub project: String,
    pub kind: String,      // "goal" | "annual" | "quarter" | "epic" | "slice"
    pub native_id: String,
    pub milestone: Option<String>, // set for slices
}

// Task gains an optional native anchor
pub struct Task {
    pub id: Id,                 // factory-internal (workflow key)
    pub native_ref: Option<NativeRef>, // the real slice/epic this task realizes
    // … existing fields
}
```

`Pipeline::decompose` then maps a **native slice** (or a batch of slices under an epic) to work
packages, rather than the fixed `scaffold/implement/test`. The factory's `Receipt` already binds
`git_revision`, matching the native receipt contract; the factory's `Claim`/`Lease` either stay
factory-internal (model a) or map onto native claim keys (model b).

## Ownership decision (two models)

- **(a) Registered executor — tight.** The factory is an execution owner the native side accepts;
  its receipts become native receipts, so Okayr displays them with no extra work. Requires
  extending the native execution owner's route + coordination.
- **(b) Consume + report — loose, reversible.** The factory reads slices, produces code + receipts
  in its own store, and reports evidence back; Okayr's execution view stays native-only until
  explicitly bridged. Safe first step, less automatic visibility.

Recommend **(b) first**, graduate to (a) once the native owner's write route is proven.

## Sequence

1. **Run the factory loop live** (see `next-steps.md`). Non-negotiable first — both systems are
   unproven in runtime, and integrating first compounds that.
2. **Align identities** — add `NativeRef` to `Task`, switch `decompose` to consume slices.
3. **Pick the ownership model** — (b) consume+report, then (a) registered executor.
4. **Surface in Okayr** — Okayr renders the factory's execution state read-only.

## Decisions needed (from you)

1. **Ownership model** — (a) registered executor vs (b) consume + report?
2. **Transport** — does the factory read slices via Okayr's `/v1` read API, or directly from the
   native files (`dev-projects-registry.yaml`, etc.)? (Okayr's API is authenticated loopback; the
   native files are authoritative but require the parser/owner path.)
3. **Where the factory runs relative to the NUC** — the factory and the native files must be
   reachable from each other; this ties into the NUC deployment in `next-steps.md`.

## Boundaries to preserve (both plans already agree)

- Okayr owns planning edits + approvals; the factory owns execution; Okayr **renders** execution.
- A successful factory merge never *is* approval — it must flow through the native approval path.
- No second goals/OKR/epic/execution authority, no shadow records.
