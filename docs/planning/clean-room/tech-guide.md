# Tech Guide — Clean-Room Software Factory (on Goose)

Concrete stack, pinned versions, conventions, and dev-environment setup. Grounded in the Phase 5/6 kickoff research (`findings.md`) and the user's preferred stack (`~/.claude/preferred-tech-stack.md`).

## Language & Runtime

- **Rust 1.90.0** (edition 2024). Pinned to Restate's MSRV (raised from 1.85 → 1.90). This overrides the preferred-stack "1.83+" note.

## Frameworks

| Concern | Choice | Version | Rationale |
|---------|--------|---------|-----------|
| HTTP (control plane) | Axum | 0.8.x | preferred stack; matches `sfctl` API |
| Async runtime | Tokio | 1.x | preferred stack |
| Durable execution | **restate-sdk** | **0.12.1** | replay journal, one-binary server, user decision (D3) |
| DB driver | SQLx | 0.8.x | compile-time-checked queries; preferred stack |
| Serialization | serde + serde_json | 1.x | preferred stack |
| CLI | clap (derive) | 4.x | `sfctl` subcommands |
| HTTP client (→ gateway) | async-openai (or reqwest) | latest | OpenAI-compatible `/v1/chat/completions` |
| Error handling | anyhow + thiserror | 1.x / 2.x | preferred stack |
| Logging/tracing | tracing + tracing-subscriber | 0.1/0.3 | observability |
| Config | dotenvy | 0.15.x | env contract |

## Dependencies (pinned)

- `restate-sdk` **0.12.1** (2026-09-22) — durable workflows. Note: v0.11.0+ uses struct impl-block API, not the deprecated trait API.
- `axum` 0.8, `tokio` 1, `sqlx` 0.8 (features: `runtime-tokio`, `tls-rustls`, `postgres`).
- `clap` 4 (derive feature).
- `async-openai` (for gateway calls) or plain `reqwest` 0.12 + `serde`.
- `serde` 1 + `serde_json` 1.
- `ulid` (or `uuid` v7) for entity IDs (time-sortable primary keys).

## Dependencies added for R13–R16 (improvements)

- **R13 (command policy)**: a shell parser for AST tokenization of pipes/chains/nesting — candidates `tree-sitter-bash` (reuses the R16 tree-sitter stack), `conch-parser`, or `brush-parser`; plus `toml` for the rule set. *(decide in the R13 implementation task)*
- **R14 (masking)**: `regex` + `once_cell` (`Lazy<RegexSet>`) for the scrub patterns.
- **R15 (task graph)**: no new deps (a `Task` type in `shared` + graph logic in `driver.rs`).
- **R16 (memory)**: `tree-sitter` + `tree-sitter-rust` (and per-language grammars) for the AST graph; **`pgvector`** (Postgres extension) for semantic search — requires switching the compose image to `pgvector/pgvector:pg16`. Embeddings come from **Bifrost** (no new client).

## Conventions

- **Formatting/lint**: `rustfmt` + `clippy -D warnings`. Edition 2024.
- **Typing strictness**: no `unsafe` in application code; `#[deny(clippy::all)]`.
- **Import style**: grouped (std, external, crate).
- **Naming**: snake_case; modules `handlers/`, `models/`, `auth/`, `workflows/`, `qualifier/`, `wall/`, `gates/`.
- **Error handling**: `thiserror` for domain errors, `anyhow` at the binary boundary.
- **Secrets**: env vars only (`.env`, gitignored); never in code, never in agent context.

## Testing stack

- **Unit**: Rust `#[cfg(test)]` + `tokio::test`; property tests via `proptest` for qualifier scoring.
- **Integration**: `sqlx` test DB (or `sqlx::test`), Restate in-process test harness, and a full-loop integration test that runs Goose against a tiny greenfield spec.
- **CLI**: `assert_cmd` for `sfctl` subcommands.
- **Wall**: a deterministic evaluator test that verifies a scenario body is *unreachable* by the generator (negative test).

## Dev Environment

- **Required services**: Postgres 16 (Docker Compose), `restate-server` binary, **Bifrost gateway** (external, operator-run — set `BIFROST_URL`), Goose (`cargo install goose` or binary), git.
- **Env contract** (`.env`):
  - `DATABASE_URL`, `RESTATE_URL`, `BIFROST_URL`, `BIFROST_VK`, `BIFROST_ADMIN_KEY`, `GOOSE_BIN`, `WORKTREE_ROOT`.
- **Setup**: use [the staged setup guide](../../../clean-room/SETUP.md). `./setup.sh check`
  validates configuration without starting services; `up` explicitly starts Compose infrastructure;
  `register` runs only after the host SDK and its reviewed private ingress are available.
  Restate admin is `127.0.0.1:9070`, ingress is `127.0.0.1:8090`. `RESTATE_IMAGE` must identify
  a reviewed server release/digest; SDK 0.12.1 is not a server-version pin. `POSTGRES_PASSWORD`
  has no default. The current loopback SDK listener is not assumed Docker-reachable.

## Build & Run commands

```bash
cargo build              # build
cargo test               # unit + integration
cargo clippy -- -D warnings
cargo fmt --check
cargo run -p sfctl -- submit --title "..." --description "..."
cargo run -p control-plane   # start the HTTP API
```

## CI shape (sketch — CI itself out of scope for MVP)

1. `fmt --check` → 2. `clippy -D warnings` → 3. `test` (unit + integration) → 4. a single end-to-end loop smoke test (submits a tiny intent, asserts a merged diff + wall pass).

## Alignment with Architecture

| Component | Stack choice |
|-----------|--------------|
| Control plane | Rust + Axum + restate-sdk + SQLx |
| Durable state | Restate (workflow journal) + Postgres (queryable) |
| Execution plane | Goose (headless `goose run`) in git worktrees |
| Verification plane | Rust evaluator crate (`crates/evaluator`) |
| Model gateway | Bifrost (external, operator-run) |
| CLI | clap (`crates/sfctl`) |

## Debate Outcomes

The architecture debate (see `consensus-plan.md`, `debate-transcript.md`) validated and sharpened the stack choices here. The tech-guide debate is folded into that same adversarial pass — every volatile tech decision below was raised and resolved by the same 5 personas. Changes that landed in this guide:

- **Restate storage**: confirmed embedded log + RocksDB + S3 snapshots (NOT Postgres). Postgres in this guide is the *read projection* only, not the source of truth (consensus R3).
- **Two-binaries note**: the execution plane is a separate worker daemon, not a control-plane subprocess (R4). The `goose run` call belongs to that worker.
- **`Receipt` contract** (R6) replaces the loose "exit code + git diff"; parse `--output-format json` stdout.
- **Gateway**: **Bifrost** (resolved 2026-10-15) — the operator runs it externally on their network. Inference uses the OpenAI-compatible `/v1/chat/completions` with the `x-bf-vk` virtual-key header; budgets are read from the governance API (`/api/governance/virtual-keys`), and the pure `gate_call` defaults-deny when that read fails (R7). See `decisions/2026-10-15-gateway-bifrost.md`.
- **Rust MSRV 1.90** already reflects Restate 0.12.1's requirement.
- **Cost anchor**: historical planning estimate only; actual gateway prices and spend require runtime evidence. O1 is resolved to hosted open-weights.
- **Operator authentication (2026-10-26)**: separate local operator account, kernel Unix peer credentials and action-bound single-use approvals; no MFA claim. See `decisions/2026-10-26-operator-auth.md`. Axum/Tokio Unix transport and feature-gated Restate approval journal compile against the lockfile. The journal remains unregistered until private ingress, identity separation and authoritative action eligibility are verified.

## Scoped structured writer — 2026-10-28

Three-reviewer debate selects a two-file, factory-owned structured MCP writer for the uncapped owned INT-LOOP; shell policy stays unchanged. Distinct fixed executor invocation, strict bytes/identity/fences, partial-write quarantine, exact baseline/generation snapshot and isolated evaluation remain mandatory. No production activation or completed INT-LOOP is claimed. See `decisions/2026-10-28-structured-task-writer/consensus-plan.md` for the decision and discriminating pre-live gates.

## Scoped NUC administration — 2026-10-29

The user authorized existing Docker permission for scoped host-root deployment. Use reviewed fixed administrative bridges and exact-ID/config/intent checks; never give workers Docker or arbitrary root commands. Five locked role accounts and factory-only root directories are installed, with bo retained as the distinct human operator. No shared restart/reboot or login-key/sudo/group change follows. The three-reviewer NUC supervisor debate is recorded in `decisions/2026-10-29-nuc-root-supervisor/consensus-plan.md`; production admission remains gated on deployed socket/network namespace, supervisor/worker/recovery and complete INT-LOOP evidence. See `verification/2026-10-29-nuc-identities/README.md` for precise paths, permissions and preservation limits.

### NUC native launcher access amendment (2026-10-30)

The selected callback parent is root:sfgoose-control mode0710. The relay traverses
it through a pinned O_PATH descriptor, while only root can replace the socket;
the model receives only its socket bind mount. Keep the native launcher cap-empty.
Follow the [reviewed amendment](decisions/2026-10-30-native-launch-read-access/consensus-plan.md)
for versioned package/helper updates, callback lifecycle exclusion and actual
native UID/capability controls. This updates the local NUC implementation boundary;
its integration gates must pass before admission, and the previous closed task
and all existing services/data remain preserved.

### Root-attested finalization (2026-10-30)

The [three-reviewer decision](decisions/2026-10-30-root-finalization/consensus-plan.md)
keeps finalization in the same exclusive claim journal and preserves the permanent
launch reservation. A versioned immutable outcome and outbox envelope records
evaluated pass, evaluated fail or authenticated unknown; unknown spend remains
explicit. PostgreSQL is an idempotent, reconstructible projection. Status,
reexport and exact-evidence eligibility do not establish human approval.

Private namespace membership alone cannot authorize finalization. Before any
journal decision, the SDK requires a protected Root-published authorization for
the exact canonical task, generation and request digest. Root evidence remains
0600. A per-generation exclusive publisher/shared reader lock and a durable
pending marker created before publication deny partial or ambiguous publication.
The marker is removed only after authorization and completion records and their
directory entries have been synced. Missing, busy, unsafe or mismatching state
is a terminal denial, not a request that waits for future approval. Root, PID1,
the protected filesystem and trusted SDK code remain in the trust boundary.

The native synthetic authorization canary passed exact delivery, changed digest,
missing/unsafe authorization, UID2001 lock denial and publisher death after file
fsync but before parent fsync. This proves that bounded permission/crash control,
not production journal integration, pass/fail evaluator provenance or promotion.

### Registry administration and old SDK retirement (2026-10-30)

The [three-reviewer ingress-fence decision](decisions/2026-10-30-registry-ingress-fence/consensus-plan.md)
conditionally selects a pinned disposable experiment: Unix-only Restate admin,
fixed Root-mediated operations executed through PID1 as trusted journalUID2004,
and persistent retirement of all ungated SDK1–4 endpoints. Keep private data
permissions strict; SDKUID2000 receives no admin connection or arbitrary proxy.
The gate/SQL snapshot alone cannot fence old code, and leaving8080 available can
forward calls to old SDKs. Test that route and existing connections explicitly.

Preserve old deployment histories and all retained work. Unavailable old-pinned
work is not drained. A tested zero or explicit bounded quarantine classification,
one non-force registration receipt, serving-process attestation and all-history
replay are separate live gates. No live admin configuration or endpoint retirement
has yet been performed; namespace filtering is only a fallback if the Unix proof
fails. See the decision for exact disposable and later cutover requirements.
