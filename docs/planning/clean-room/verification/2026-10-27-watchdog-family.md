# Watchdog-owned group families — 2026-10-27

This extends the independent-watchdog component after review identified a real integration gap: the Python adapter starts execution in a new session and Rust execution supervision creates a separate shell process group. Killing only a worker's group therefore does not establish termination of its Goose/tool subprocesses. The earlier single-group fixture was not a production kill-switch pass.

## Change

A stop target now represents a bounded family of up to 16 group roots directly spawned by the watchdog. `Registry::create_family` returns an opaque target; `spawn_in_family` launches a reviewed command and retains its `Child` handle under that target. There is still no numeric PID registration or HTTP launch endpoint.

Spawn admission and stop use the same registry mutex. Stop permanently closes the family before signalling. A racing launch either completes admission while ownership is retained, so stop includes it, or fails before spawning. A timeout, failure, or repeated stop cannot reopen admission. Records and IDs never evict or reset.

Stop signals every owned group before waiting on any member, so a suspended worker does not need to cooperate or delay termination of separately owned Goose/tool groups. Each leader remains unreaped until its own group signal; WNOWAIT ownership checks, default SIGCHLD requirements and the no-post-reap-kill rule are preserved. Responses include a result per group; aggregate completion requires every retained leader to be reaped and every registered group to be absent. Ordinary in-group descendants are included by group signalling.

The `--fixture-family-server` mode directly launches three harmless group roots labelled worker, Goose and tool, each with an ordinary descendant. The worker stand-in suspends itself with SIGSTOP. These are three sibling groups owned by the watchdog, not the actual execution/Goose binary chain. That distinction is deliberate and limits what this fixture proves.

## Evidence

Test-first RED: five missing family-API/result-field compilation errors (`/tmp/sfactory-watchdog-family-red.log`).

GREEN:

- `cargo test --locked --manifest-path clean-room/Cargo.toml -p watchdog --all-features`: **8 unit tests + 2 separate-process integration tests passed**, no failures or ignored tests (`/tmp/sfactory-watchdog-family-green.log`).
- `cargo clippy --locked --manifest-path clean-room/Cargo.toml -p watchdog --all-features --all-targets -- -D warnings`: passed.
- Scoped rustfmt and `git diff --check`: passed.

The new unit tests prove multi-group aggregation, permanent admission closure, and eight races between family launch and stop. In each race, a successfully launched group appears in the completed stop result, while losing launches are rejected. Existing wrong-identity, unowned-target, natural-leader-exit and post-reap numeric-ID reuse regressions remain green.

The new black-box test verifies three distinct actual PGIDs and six live fixture processes; confirms the worker stand-in is stopped rather than cooperating; authenticates to the separate watchdog; and observes all three leaders killed/reaped, all three descendants gone and all three groups absent. Exact repeat stop returns the same per-group results. No existing user process or standing service was targeted. Fixture-only identity and credential limitations remain unchanged.

## Remaining runtime integration — not closed

Actual execution and Goose still spawn their own children. They do not call this family API. Production needs a trusted spawn broker that binds a family to the immutable task/lease/worker and becomes the actual parent of every managed group root. Both spawn and reap ownership must move together; adding a second waiter to execution's `ProcessGroup` would violate its ownership fence. The broker must preserve bounded output, policy enforcement, process deadlines and receipt linkage, without an unmediated local-spawn fallback.

Directly owning all intended roots still does not contain an arbitrary descendant that calls setsid or changes groups. Verified OS containment or another safe ownership mechanism is required before claiming whole-tree cleanup. PID scanning followed by numeric kills is not an accepted substitute.

The component remains unactivated. Distinct account/key provisioning, private listener and spawn-channel authentication, real worker/Goose integration, escaped-descendant containment and watchdog-crash recovery remain blockers. G-05/R9 is partial; the factory kill-switch gate has not passed.
