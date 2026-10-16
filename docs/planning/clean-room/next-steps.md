# Next Steps — Clean-Room Software Factory

**Handoff doc.** Created 2026-10-16 to move this work from the sandboxed session into a
non-sandboxed harness (local terminal or the NUC) and continue.

---

## Where things stand

**Planning** — complete. `docs/planning/clean-room/` holds the full plan: `phased-plan.md`,
`consensus-plan.md` (resolutions R1–R16), `improvements-plan.md` (R13–R16), `architecture.md`,
`tech-guide.md`, `data-map.md`, `user-stories.md`, `debate-transcript.md`, `decisions/`.

**Implementation** — complete on the code side: 5 crates, **61 tests, clippy clean**, committed.

```
1fb9829 chore: stop tracking Restate runtime data
7ffaf59 feat(driver): wire the credential gate (Gate 3 / R8)
fc04d5d feat(driver): enforce the budget gate (R7 per-unit ceiling)
e7dbdcd feat(driver): wire the runtime callbacks (build -> wall -> gate -> merge)
a75099d feat(driver): pipeline orchestration (decompose -> dispatch -> build -> evaluate -> merge)
69bbb93 feat: clean-room software factory on Goose (base + R13-R16)
```

**Not done** — the loop has **never executed end-to-end**. Every compile + unit/integration test
passes, but the running system (control-plane serving, Restate workflow executing, goose running,
Bifrost calling) has not been exercised. That is the whole point of moving off the sandbox.

---

## Immediate next step: run the loop live

### 1. Build + test
```bash
cd clean-room
cargo test                 # expect 61 passed
cargo build --features ast -p control-plane   # R16 tree-sitter
```

### 2. Bring up infra
```bash
export OPENROUTER_API_KEY=... LITELLM_MASTER_KEY=...   # if using the compose gateway
./setup.sh                 # docker compose up (restate + postgres) + register the SDK service
```
> Bifrost is **external** (your network) — set `BIFROST_URL`. The compose only runs Restate + Postgres.

### 3. Start the control plane (Axum :8081 + Restate SDK :9080)
```bash
export DATABASE_URL=postgres://sfactory:sfactory@localhost:5432/sfactory
cargo run -p control-plane --features restate &
```

### 4. Drive the pipeline
```bash
cargo run -p sfctl -- submit --title "hello" --description "a hello CLI" --acceptance "has a passing test"
# → returns { intent_id, lane: "dark" }
curl -s localhost:8081/v1/pipelines/<intent_id>            # stage + task DAG
curl -s -X POST localhost:8081/v1/pipelines/<intent_id>/dispatch   # submit work packages to Restate
```

### 5. Run the worker (goose)
```bash
export SFACTORY_PROMPT="<the greenfield spec>"
export SFACTORY_WORK_PACKAGE_ID=<task id, e.g. <intent_id>:scaffold>
export SFACTORY_WORKTREE=/tmp/sfactory-worktrees/wp1
export SFACTORY_PIPELINE_ID=<intent_id>
export SFACTORY_CONTROL_URL=http://localhost:8081
export SFACTORY_SHIMS_DIR=$PWD/shims       # R13 policy shim on PATH
export RESTATE_URL=http://localhost:8080   # the Restate runtime ingress
cargo run -p execution
```
The worker runs goose, resolves the workflow promise, and reports the receipt to
`POST /v1/work-packages/{id}/result` → build → wall → gate → merge.

---

## Environment contract

| Var | Purpose | Default |
|-----|---------|---------|
| `DATABASE_URL` | Postgres (read projection + memory) | — |
| `RESTATE_URL` | Restate runtime **ingress** | `http://localhost:8080` (host-mapped `:8090` in compose) |
| `BIFROST_URL` | your Bifrost gateway | — |
| `BIFROST_VK` | virtual key (sent as `x-bf-vk`) | — |
| `BIFROST_ADMIN_KEY` | management bearer (budget reads) | — |
| `GOOSE_BIN` | goose binary | `~/.local/bin/goose` |
| `WORKTREE_ROOT` | disposable worktrees | `/tmp/sfactory-worktrees` |
| `SFACTORY_SHIMS_DIR` | R13 policy shim dir (prepended to PATH) | — |
| `SFACTORY_CONTROL_URL` | control plane base (worker callback) | `http://localhost:8081` |
| `SFACTORY_PIPELINE_ID` | pipeline id for the worker callback | — |
| `SFACTORY_POLICY` | R13 rules file | built-in defaults |

**Ports** — control-plane Axum `:8081`; Restate SDK service `:9080`; Restate runtime `:8080`
(ingress) / `:9071` (admin); Postgres `:5432`; Bifrost (your network).

---

## Deployment to the NUC

1. **Code there.** Push the repo to a remote and clone, or `rsync` `clean-room/`. (6 commits exist
   locally; no remote is configured yet.)
2. **Rust 1.90+** on the NUC (edition 2024). Build **natively** — do not cross-compile from the Mac.
3. **Infra on the NUC (or reachable):** `restate-server`, Postgres — use the
   **`pgvector/pgvector:pg16`** image (R16 needs the `vector` extension; the plain `postgres:16`
   image lacks it). Bifrost is already in your network.
4. **goose** on the NUC (the worker).
5. **Config** — point the env vars above at the NUC's services.

### The one portability gap: agent isolation

R1 uses **macOS Seatbelt** (`sandbox-exec`) — Mac-only, and it is *not in code yet* (documented
design). On a **Linux** NUC the equivalent is **bubblewrap** (`bwrap`), firejail, or namespaces.
The rest of the execution plane is portable: the POSIX shim (`shims/sh`), `process_group` + `kill
-pgid`, and the masking/policy are all Linux-compatible. So this is a swap of the OS-sandbox layer,
not a rewrite. (Containers / microVMs are the documented escalation path.)

---

## Remaining work (ranked)

1. **Run the loop live** (above) — the single biggest gap. Expect integration bugs the unit tests
   can't see: Restate registration, the workflow↔worker promise handshake, `goose run` flags
   (`--output-format json` shape), and the callback wiring.
2. **Holdout-scenario evaluation** — the wall currently runs only its *deterministic* half
   (`evaluator::verify_worktree`). The LLM pre-filter + holdout scenarios (R2) need an ephemeral
   deployment — not built.
3. **Linux isolation** — implement bubblewrap/namespaces for R1/R10 in the execution plane
   (currently macOS-Seatbelt design only).
4. **`parse_rust` test** — R16's tree-sitter parse compiles under `--features ast` but has no test.
5. **Open items O2–O6** (`consensus-plan.md`): gate sample size, qualifier calibration, operator
   auth/MFA, scenario authoring/drift, supply-chain.
6. **Phases 10–14** — integration tests (INT-02…INT-LOOP), full verification, delivery, gap audit.

---

## Known gotchas

- **Sandbox restrictions hit during this session** (why work moved here): `crates.io` network
  denied, `.git` creation denied, `~/.cargo/registry` writes denied, local port binding denied
  (`bind: PermissionDenied`), background processes (`nice`) denied. All are gone in a normal shell.
- **Restate storage** — Restate 0.12 uses its embedded log + RocksDB + S3 snapshots, **not
  Postgres**. `clean-room/restate-data/` is runtime data (now `.gitignore`d) — don't commit it.
- **tree-sitter versions** — pinned to `0.25` / `tree-sitter-rust 0.24`; the API (`LANGUAGE.into()`)
  is version-sensitive. It compiles, but verify against the grammar on the NUC if you bump.
- **Bifrost config** — `gateway/config.json` model IDs are best-effort; adjust to your Bifrost's
  exact provider/model names. The budget read uses `/api/governance/virtual-keys`.
- **`allowLocalBinding`** — written to `.claude/settings.local.json`, but it did not apply to the
  session that wrote it; a fresh session picks it up.

---

## How to resume

1. Read `docs/planning/clean-room/consensus-plan.md` (R1–R16) + `improvements-plan.md` (R13–R16) —
   the decisions are all recorded there.
2. `git log --oneline` — six commits tell the story; the working tree is clean.
3. Run the loop (Immediate next step) and fix whatever the live run surfaces.

**Architecture in one line:** Rust control plane (Restate durable state + Postgres read projection)
→ Goose workers in disposable git worktrees (policy-shimmed, masked) → an isolated verification
"wall" → three human gates (budget, first-promotion, credentials) → merge.
