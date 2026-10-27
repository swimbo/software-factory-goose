# Findings

Research discoveries, external content, and technical decisions. External/untrusted content is written here, never into `phased-plan.md`.

## Pain Point Research

### Skipped

**Skipped (user-provided research).** The user supplied `dark-software-factory-report.md` (37 KB, dated October 2026) as the primary research basis. Per the bo-planning rules, Phase 2 may be skipped when the user provides their own research. The report contains the pain-point synthesis this phase would otherwise produce.

Key pain points / unmet needs the report surfaces (used to ground user stories):

1. **Sycophancy / self-declared victory** — an LLM that both writes and grades its own change "declares victory on what it just produced"; a test stored next to the implementation gets "lazily rewritten to match the code, not the other way around." → the *wall* with holdout scenarios the generator can't reach. (report §4, StrongDM pattern.)
2. **Vendor benchmark inflation** — provider-reported SWE-bench scores overshoot independent runs by double digits; building on vendor numbers is a trap. → anchor model choices on independent runs only. (report §3)
3. **"Automating chaos"** — skipping codified knowledge (ADRs, domain rules, standards) before wiring agents "only amplifies the gap." → write `AGENTS.md` + codified knowledge first. (report §4, §10)
4. **Cost blow-up before it's discovered** — retries unbounded, no spend cap; StrongDM ~$1,000/day per engineer-equivalent. → budget gate + retry caps. (report §6, §10)
5. **The scaffold matters as much as the model** — same model scores 43.2% on one scaffold and 59.8% on another (16-point gap). → harness engineering is a first-class competency, not a config detail. (report §3)
6. **Isolation theater** — sandboxing without a real boundary (no disposable checkout, inherited secrets) limits blast radius but doesn't replace review; Docker alone isn't sufficient. → disposable worktrees, deny-by-default network, brokered credentials. (report §5.5, §11)

These six themes are the direct motivation for the wall, qualifier, and gates in the scope.

## Phase Kickoff Research

Kickoff research targets the volatile tech decisions (Restate, Goose, gateway/models) that training data cannot ground for a 2026 stack. Three parallel research agents; results folded into `tech-guide.md` (Phase 6) and `architecture.md` (Phase 5).

### Phase 5/6 Kickoff Research — Restate (RESOLVED)

- **Crate**: `restate-sdk` (with internal `restate-sdk-core`), latest stable **0.12.1** (2026-09-22). Repo `restatedev/sdk-rust`.
- **API**: struct impl-block + `#[service]`/`#[object]`/`#[workflow]` macros + `#[handler]` methods; context type infers semantics. **v0.11.0 dropped the old trait-based API.**
- **Deployment**: single self-contained Rust binary `restate-server` (BSL license), no external DB/broker. Managed: Restate Cloud (free tier) + BYOC. Kubernetes Operator for prod.
- **Durability**: **replay-based journal** (not checkpoint-resume) — side-effecting steps recorded before result observed; exactly-once; `Idempotency-Key` dedup. **Storage correction**: embedded replicated log ("Bifrost") + embedded RocksDB + S3/object-store snapshots. **Postgres-backed storage has been superseded** — current docs describe only the embedded store. (Reverses the earlier "Restate backs onto Postgres" assumption.)
- **Long-running**: `ctx.awakeable::<T>()` + `resolve_awakeable`, named signals, durable promises, `ctx.sleep`. Handlers suspend indefinitely. Default inactivity timeout 1 min; raise to ~3 min for LLM calls.
- **MSRV 1.90.0** (edition 2024). Ingress/scope-keys need Restate ≥1.7 + SDK ≥0.11.

### Phase 5/6 Kickoff Research — Goose (RESOLVED)

- **Repo moved**: `block/goose` → **`aaif-goose/goose`** (Agentic AI Foundation / Linux Foundation). Docs at **goose-docs.ai**. Still Rust, Apache-2.0. Latest **v1.49.0** (2026-09-03), ~weekly cadence, 53k+ stars.
- **Headless CLI — confirmed**: `goose run` runs a task and exits. Flags: `-t/--text`, `-i/--instructions` (file or `-`), `--no-session` (ephemeral, ideal for subprocess), `-s/--interactive`, `--output-format json`, `--provider`/`--model`, `--recipe`. Env: `GOOSE_MODE=auto`, `GOOSE_MAX_TURNS`, `GOOSE_CONTEXT_STRATEGY=summarize`. **Exit codes signal success/failure** (`if ! goose run ...`). Approval-requiring tools fail-closed in headless mode (no hang).
- **Recipes**: YAML (or JSON) — `version`, `title`, `description`, `instructions`, `prompt`, `settings` (`goose_provider`/`goose_model`/`temperature`/`max_turns`), `extensions`, `parameters`, `retry`, `sub_recipes`. Reviewable/diffable.
- **Models**: custom providers via `~/.config/goose/custom_providers/*.json` with `"engine": "openai"` (also `anthropic`, `ollama`), `base_url`, `api_key_env`. Env `OPENAI_HOST`/`OPENAI_BASE_PATH`. 15+ built-in providers; **v1.49.0 added Z.ai GLM-5.3 + DeepSeek/Alibaba OpenAI-compat**. → pointing at a Bifrost/LiteLLM gateway via `engine:openai` + `base_url` works.
- **MCP**: "70+ extensions" via MCP + ACP (`goose serve`). Configured in config/profile YAML.
- **Git/worktree: external** — Goose has no native worktree creation; the factory layers isolation. Permission modes: `GOOSE_MODE` auto/smart_approve/approve/chat + per-tool `permission.yaml`. No native diff-return API — recover diff via `git diff` in the wrapper.

### Phase 5/6 Kickoff Research — Gateway + open-weights (RESOLVED)

- **LiteLLM** — market leader, now with a **Rust core** (rebuilt from Python; 0.66ms p99). Self-hosted, one OpenAI-compatible endpoint for 140+ providers / ~1,800 models; auto-routing (cheap↔cheap, frontier↔hard); virtual keys, per-key/team/project budgets, spend caps, central logging. Enterprise adds SSO/RBAC/audit.
- **Bifrost** (Maxim AI) — Go single-binary, 20+ providers (vLLM/SGLang/Ollama), semantic caching, **hierarchical budgets**, immutable audit logs; 11µs overhead @ 5k RPS.
- **OpenRouter** — hosted/managed, one key, failover, +5.5% fee (third-party data path).
- **Models (open-weights, ~15–20× cheaper than Claude Opus)**:
  - **GLM-5** (Z.ai): 744B/40B-active, MIT, 200K ctx, $1.00/$3.20 per M; GLM-5.1 $1.40/$4.40; GLM-5.3 latest (Oct 2026). Self-hostable via vLLM 0.19+/SGLang.
  - **DeepSeek-V4**: V4-Pro $1.32/$3.96 (1M ctx); V4.1-Flash $0.30/$1.20. Open-weights V3/R1 under **DeepSeek Model License (not MIT) — legal review advised**.
  - **MiniMax M2.5** (MIT): 80.2% SWE-bench Verified, $0.30/$1.20.
  - **Kimi K2.5** (Moonshot): $0.60/$3.00, strong LiveCodeBench (85.0).
  - **Qwen3.7/3.8**: ~$0.40/$1.60 cheap agent/coding tier.
- **Rust calling pattern**: no gateway-specific SDK needed — hit `/v1/chat/completions` via `async-openai` (any `base_url`) or plain `reqwest` + `serde`. LiteLLM has `litellm-rust`.
- **Recommendation**: self-host **LiteLLM** (Rust core) or **Bifrost** as the credential-brokering gateway; call from Rust via `async-openai`; route cheap-task → M2.5/Qwen/GLM-5-Flash, hard-task → GLM-5.1/DeepSeek-V4-Pro/Kimi K2.5.

## code-machine analysis (2026-10-15)

A comparative review of the `code-machine` agent CLI (forked from Pi) surfaced four best practices our plan lacked, folded in as R13–R16 (see `consensus-plan.md` + `improvements-plan.md`):

1. **Deterministic pre-execution command policy** — code-machine tokenizes piped/chained/nested shell commands into an AST and checks them against declarative TOML rules *before* execution (`shell-parser.ts`, `default-policies.ts`). Our plan had OS isolation + credential scoping + budget, but nothing inspecting the *command*. → **R13**.
2. **Output masking before context** — it scrubs env tokens, creds, and API keys from tool outputs before they enter the model (`tool-output-masking.ts`, `output-guard.ts`). Our R10 covered secret *injection*, not *leakage*. → **R14**.
3. **Coordinator + explicit task-dependency graph** — `TaskCreate`/`TaskUpdate` with `addBlockedBy`/`addBlocks`, and "each subagent returns a concise summary" to avoid flooding the coordinator's context. A better-specified version of our prose goal cascade. → **R15**.
4. **Dynamic codebase memory** — persisted AST knowledge graph (`graphify`) + ChromaDB semantic memory, injected into the system prompt. Our "codified knowledge" (BCG pillar 2) was static markdown. → **R16**.

**What it validated:** subagents in isolated git worktrees ⟷ R10/D7; coordinator/worker split ⟷ R4; credential scoping so a worker can't reach upstream ⟷ R8.
**What doesn't transfer:** interactive permission prompts / YOLO mode (we relocate humans to gates); Homebrew/package-registry distribution; TUI; multi-provider adapters (Bifrost covers it).

## Technical Decisions (resolved)

| Decision | Choice | Rationale | Artifact |
|----------|--------|-----------|----------|
| Scope | Working MVP factory | user decision | phased-plan.md#decisions D1 |
| Language | Rust | matches Goose + preferred stack | D2 |
| Durable substrate | Restate | replay audit, one binary, Rust SDK | D3 |
| Models | Open-weights via gateway | cost-rational, no lock-in | D4 |
| Workload | Greenfield demo | self-contained first slice | D5 |
| Repo | Monorepo (in `clean-room/`) | user decision + "put in /clean-room" | D6 |
| Isolation | Git worktrees | pragmatic MVP, report's layering | D7 |

## Known Unknowns / Questions to Revisit

- Gateway choice — **RESOLVED (2026-10-15): Bifrost** (Maxim AI). The operator already runs Bifrost on their network, so the factory points at it via `BIFROST_URL` (no container). Switched from the earlier LiteLLM default. See `decisions/2026-10-15-gateway-bifrost.md`.
- Restate license is BSL (not OSS) — acceptable for self-host, but flag for any redistribution intent.
- DeepSeek open-weights are under DeepSeek Model License (not MIT) — legal review if self-hosting DeepSeek rather than routing via API.
- Whether the factory's Postgres (for operational/queryable records) should be dropped entirely in favor of Restate's embedded store + a lightweight SQLite/JSON audit sink — see architecture debate.

## NEEDS_HUMAN_DECISION

- **O1 serving backend — RESOLVED (2026-10-13): hosted open-weights API** (OpenRouter / Z.ai / together.ai). Self-hosted GPUs deferred. See `consensus-plan.md` O1.
- **O4 operator authentication — RESOLVED (2026-10-26):** user chose a separate local operator account and action-bound approval channel, with no MFA claim. See `decisions/2026-10-26-operator-auth.md`. Distinct-account provisioning, private ingress, exact-evidence eligibility, and replay-safe execution still require implementation and live verification; the decision itself is no longer blocked.
- Remaining open items: O2 gate sample size, O3 qualifier calibration, O5 scenario authoring/drift, O6 supply-chain. Existing scoped defaults do not establish production readiness.

## Phase 10 Kickoff Research

2026-10-26: this project uses Rust/CLI integration testing, not browser Playwright. The local toolchain is rustc/cargo1.94.0; package MSRV remains1.90. Checked local `cargo test --help` and the [official Cargo test reference](https://doc.rust-lang.org/cargo/commands/cargo-test.html): `--workspace --all-features` includes the optional Restate/AST code, `--all-targets` covers libraries/binaries/integration tests/examples, and `-- --list` provides test discovery. Documentation tests are a separate run when selecting all targets. CLI fixtures use Cargo-provided binary paths and observable status/JSON outcomes, without a new testing dependency. Keep lockfile/offline verification separate from live external-service acceptance.

## Follow-ups from current verification

The pinned Goose protocol audit (`verification/2026-10-26-goose-protocol.md`) invalidates the assumption that its `completed` JSON field proves task completion or hooks enforce all tool masking. The prepared `decisions/2026-10-26-goose-tool-boundary.md` awaits confirmation for its required focused debate. Keep runtime refusal in place. O4 remains resolved; the private-ingress note identifies implementation proof requirements, not a new identity choice.
