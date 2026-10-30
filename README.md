# Software Factory Goose

A Rust software factory that coordinates Goose coding workers, durable Restate workflows, a PostgreSQL read projection, independent evaluation, and an external Bifrost model gateway.

**Status:** experimental, under active development. Local diagnostic APIs and component tests are usable; a general-purpose, production-ready autonomous factory is not established. Host-specific Linux integration is evolving. See [current progress](docs/planning/clean-room/progress.md) and [the phased plan](docs/planning/clean-room/phased-plan.md) for exact evidence and remaining gates. Passing a local test does not authorize worker admission or promotion.

## Architecture

The intended flow is intent → qualification → task graph → controlled worker execution → independent evaluation → human-approved promotion.

| Component | Responsibility | Source |
| --- | --- | --- |
| Control plane | Qualification, workflow coordination, budgets, approvals, diagnostic HTTP API | `clean-room/crates/control-plane` |
| Execution | Goose command construction, tool policy, bounded subprocess supervision, output masking | `clean-room/crates/execution` |
| Evaluator | Exact-revision checks, isolated candidate tests, protected holdout handling | `clean-room/crates/evaluator` |
| Watchdog | Independent stop authority, owned process families, trusted launch components | `clean-room/crates/watchdog` |
| CLI | Diagnostic HTTP commands and provisioned Linux operator sockets | `clean-room/crates/sfctl` |
| Shared | Common types, schemas, configuration and contracts | `clean-room/crates/shared` |

Restate is intended to own durable workflow authority; PostgreSQL is a queryable projection. The default HTTP server still uses diagnostic in-memory state. It must not be treated as the authoritative production workflow. Bifrost runs separately and supplies model routing and governance. Goose belongs behind the reviewed worker boundary.

## Prerequisites

- Git and Rust **1.90 or newer**, including Cargo, rustfmt and Clippy (edition 2024).
- Python 3 for deployment component tests and tooling.
- Bash for the setup helper and its fixture tests.
- Docker with Compose for optional local PostgreSQL/Restate infrastructure.
- For actual workers: the reviewed Goose build, an operator-managed Bifrost gateway, protected credentials and the relevant platform isolation/identity provisioning.

The workspace locks dependencies in `clean-room/Cargo.lock`. Restate Rust SDK **0.12.1** is not a Restate server image version. Some evaluator tests require macOS Seatbelt and Xcode Command Line Tools; private operator/runtime tooling requires the provisioned Linux host. Cross-platform component compilation does not prove platform isolation.

## Quick start: build and inspect

```bash
git clone https://github.com/swimbo/software-factory-goose.git
cd software-factory-goose/clean-room
cargo build --locked --workspace
cargo run --locked -p sfctl -- --help
cargo run --locked -p sfctl -- private --help
```

These commands build the code and display CLI usage without starting infrastructure or workers. Dependency downloads require network access; use `--offline` only after the dependencies are cached.

### Try the diagnostic HTTP API

In a terminal, from `clean-room/`:

```bash
# Use a shell without DATABASE_URL for the in-memory diagnostic mode.
cargo run --locked -p control-plane
```

The API listens on `127.0.0.1:8081`. In another terminal, also from `clean-room/`:

```bash
cargo run --locked -p sfctl -- --json submit \
  --title "Example intent" \
  --description "Add a small greeting program" \
  --acceptance "A test asserts the greeting output"
cargo run --locked -p sfctl -- status
# Replace INTENT_ID with the identifier returned by submit:
cargo run --locked -p sfctl -- inspect INTENT_ID
```

`--url` or `SFCTL_URL` selects another diagnostic endpoint. `--json` requests machine-readable output. Intent submission demonstrates qualification and diagnostic state; it does not launch Goose, establish durable task execution or approve promotion. Restarting this server loses its in-memory intent state. Privileged routes remain gated.

## Optional infrastructure setup

Read [SETUP.md](clean-room/SETUP.md) before starting services. From `clean-room/`, configure `RESTATE_IMAGE` with a reviewed explicit release or digest and supply `POSTGRES_PASSWORD` securely in your local environment. There is no default database password. Do not paste credentials into tracked files or shared shell transcripts.

```bash
./setup.sh check       # Validate configuration; do not start services
./setup.sh up          # Explicitly start PostgreSQL and Restate
```

`up` preserves existing containers with `--no-recreate`. It checks readiness and pgvector availability; it does not prove recovery or apply application migrations. With a correctly configured `DATABASE_URL`, starting the control plane connects to PostgreSQL and applies its migrations:

```bash
cargo run --locked -p control-plane --features restate
```

The Restate SDK listener binds to host loopback. Establish the reviewed private ingress reachable from the Restate container before setting `SFACTORY_SDK_URI` and running `./setup.sh register`. Registration performs diagnostic discovery and does not enable live workers or the approval journal. Do not broaden the listener as a connectivity workaround.

| Service | Host binding |
| --- | --- |
| Diagnostic HTTP API | `127.0.0.1:8081` |
| Restate HTTP ingress | `127.0.0.1:8090` |
| Restate admin API | `127.0.0.1:9070` |
| Host SDK listener, with `restate` feature | `127.0.0.1:9080` |
| PostgreSQL | `127.0.0.1:5432` |

Named volumes hold PostgreSQL and Restate data. Do not use `docker compose down -v` as troubleshooting: it deletes persistent data. Configuration changes do not migrate existing volumes or change existing database credentials.

## Configuration

| Variable | Purpose |
| --- | --- |
| `DATABASE_URL` | Optional PostgreSQL connection; enables projection connection/migrations |
| `RESTATE_IMAGE` | Required explicit server image for Compose setup |
| `POSTGRES_PASSWORD` | Required local database password for Compose setup |
| `PGVECTOR_IMAGE` | Optional reviewed pg16 image override |
| `SFACTORY_SDK_URI` | Reviewed container-reachable private SDK URI for registration |
| `RESTATE_URL` | Restate ingress configuration |
| `BIFROST_URL` | External model gateway address |
| `BIFROST_VK`, `BIFROST_ADMIN_KEY` | Protected gateway inference/governance credentials |
| `GOOSE_BIN` | Reviewed Goose executable path |
| `WORKTREE_ROOT` | Worker worktree configuration |
| `SFCTL_URL` | Diagnostic CLI API URL |

Requirements differ by executable and deployment profile; consult the [technical guide](docs/planning/clean-room/tech-guide.md), source and selected runbook. The setup helper expects exported variables and does not execute `.env` as shell code. Compose may read `.env` for interpolation. Local `.env` files are ignored by Git; never commit credentials, runtime databases or private keys.

## Verification

From `clean-room/`:

```bash
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-features --all-targets -- -D warnings
cargo test --locked --workspace --all-features --all-targets
cargo test --locked --workspace --all-features --doc
bash tests/setup_test.sh
python3 -m unittest discover -s deployment -p 'test_*.py'
python3 -m unittest discover -s deployment/relay -p 'test_*.py'
```

The setup tests replace service tools with fixtures and do not start Docker. Platform-specific tests may fail closed or be gated outside their supported environment. Database/replay fixtures and live integration need their own disposable services and explicit setup; an ignored test is not evidence that its runtime gate passed. Read [execution readiness](clean-room/crates/execution/README.md), [evaluation boundaries](clean-room/crates/evaluator/README.md) and [watchdog limitations](clean-room/crates/watchdog/README.md) before interpreting results.

## Linux deployment and operator use

`clean-room/deployment/` contains host-specific provisioning, launch, registry, relay, reconciliation and canary tooling. These scripts can administer identities, services and protected paths; they are not a portable installer. Review each selected runbook and its exact host assumptions before executing it.

`sfctl private` uses protected Unix sockets on the provisioned Linux host. It offers `submit`, `inspect`, `status` and `stop`; intake profiles select fixed fixture, real or registry sockets. It enforces host-specific identity, path and credential checks. Display subcommand help for the exact arguments. A normal laptop quick start does not provision those sockets or identities.

Worker isolation, protected holdout access, gateway governance, independent stop authority, crash recovery, exact-candidate evaluation and action-bound approval are separate requirements. Diagnostic endpoints, local fixtures and host canaries establish only the boundaries they exercise. Keep production admission gated on the recorded integration evidence. Promotion requires its own explicit authorization.

## Repository map and further reading

- [`clean-room/SETUP.md`](clean-room/SETUP.md): staged setup, ports, persistent storage and registration limits.
- [`architecture.md`](docs/planning/clean-room/architecture.md): system design.
- [`consensus-plan.md`](docs/planning/clean-room/consensus-plan.md): architectural decisions and requirements.
- [`tech-guide.md`](docs/planning/clean-room/tech-guide.md): stack and development conventions.
- [`progress.md`](docs/planning/clean-room/progress.md): dated implementation evidence and current blockers.
- [`decisions/INDEX.md`](docs/planning/clean-room/decisions/INDEX.md): decision index.
- [`verification/`](docs/planning/clean-room/verification): scoped test and runtime evidence; historical results are not current certification.
- [`dark-software-factory-report.md`](dark-software-factory-report.md): background research.
- `clean-room/gateway/`, `clean-room/patches/`: gateway examples and reviewed worker patches.

This project retained its Git history when split from the earlier software-factory checkout. The Stapled implementation is maintained separately.

## Contributing and Git workflow

Read the current plan and applicable `AGENTS.md` before changing runtime behavior. Keep changes scoped, preserve existing services/data and add meaningful tests for behavioral changes. Run the checks appropriate to your change and record platform/runtime limitations. Use `codex/` branches for agent work.

Commit completed, verified milestones and push them regularly to their upstream branch. Push before ending a work session or handing off completed work. Review staged contents for secrets and unrelated changes before every commit. Do not let completed work accumulate only locally; if a push fails, report the failure and preserve the commits. A Git push publishes source history; it does not authorize deployment, worker activation or promotion.

The Cargo workspace declares `Apache-2.0`; this checkout currently has no standalone license text. Confirm licensing terms before redistribution.
