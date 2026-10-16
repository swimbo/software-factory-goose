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
- **Setup**:
  ```bash
  cargo install cargo-watch  # optional
  docker compose up -d postgres
  restate-server &           # or docker run restatedev/restate
  # Bifrost runs externally on your network; just export BIFROST_URL (+ BIFROST_VK, BIFROST_ADMIN_KEY)
  ```

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
- **Cost anchor corrected**: ~4× (not 15×), and the serving backend is O1 / NEEDS_HUMAN_DECISION.
