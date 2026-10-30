# Phase 11A harness candidate

**Disabled. Not installed in Goose or the protected relay.** This is the local
candidate runtime and evaluation interface, not a production-readiness receipt.
Current relay requests are exact-match, fixed two-turn `write_files` conversations;
rewriting them to add tools or dynamic prompts would invalidate their authority.

`CandidateSession` provides the two MCP-shaped declarations, calls, attempt-scoped
artifact pagination, stall intervention and metadata-only exchange observations.
A trusted adapter must construct it with the existing atomic spending authority,
bounded/cancellable tool transports, protected snapshot function and Rust normalizer.
No generic filesystem, shell, network, credential or evaluator capability is installed.
A tool's `read_only` classification comes from the reviewed registry, never the model.
The stable prefix includes a sorted name-only capability index and bridge usage.
Tools can be invoked without prior discovery, but never without authorization.

`Profile.messages(task)` builds new, unsigned candidate requests with static
instructions before task data. Never use it to reconstruct a signed or fenced
request. `observation` records a hash and counters, not prompt/output text; unsupported
usage/cache/cost remains `null`. Cache tokens are reported, not estimated. Provider
parameters remain unchanged until paired evaluation supports an adaptation.

## Build and verify locally

Download the official QuickJS 2026-06-04 source archive separately, extract it into
a private scratch directory, then build with `build_host.py --archive ARCHIVE
--source SOURCE --output ABSOLUTE_HOST_PATH`. The builder verifies SHA256
`b376e839b322978313d929fd20663b11ba58b75df5a46c126dd19ea2fa70ad2a` and exact
source content before compiling fresh objects. Nothing is installed or vendored.
Source: https://bellard.org/quickjs/quickjs-2026-06-04.tar.xz ; API reference:
https://bellard.org/quickjs/quickjs.html . HTTPS retrieval plus the recorded digest
pins this candidate's input; it is not a claim of upstream signature verification.

From `clean-room/`:

```sh
cargo build --locked --offline -p execution --bin sfactory_normalize
SFACTORY_TEST_SCRIPT_HOST=/absolute/script-host \
SFACTORY_TEST_NORMALIZER="$PWD/target/debug/sfactory_normalize" \
python3 -m unittest discover -s crates/execution/harness -p 'test_*.py' -v
ruff check crates/execution/harness
```

The C host has no std/os modules or module loader. It closes extra descriptors,
sets a 32 MiB JS heap cap and 512 KiB stack cap, and requires OS containment:
macOS Seatbelt denies named resources and Linux seccomp denies everything outside
its small memory/pipe/clock/exit syscall allowlist. Unsupported platforms fail closed.
No child creation is permitted, so the parent kills/reaps its exact owned process
on timeout/cancellation. The broker's existing transports must separately enforce
their own deadlines and descendant cleanup; an arbitrary blocking Python callback
is not a supported production tool transport. Memory caps concern the JS heap,
not the complete supervisor process. Limits in candidate-profile.json describe the
fixed v1 implementation, not model-editable runtime settings.

The script API is `await tools.call(name, arguments)`, `await tools.readBatch(reads)`
(up to four reviewed reads), and `await tools.fetchToolSchema(name)`. Await mutations
in order. The host processes broker frames serially; read batches alone run in parallel.
JavaScript exceptions are bounded private protocol data: complete diagnostic text
is normalized and fingerprinted for stall detection, then discarded from public
results. Sessions reject concurrent calls before any mutation.
`console.log` and the return value are collected privately, normalized as a complete
response through the existing Rust masker, and only then exposed. Oversize, incomplete,
invalid or cancelled responses release no partial text. Masking remains heuristic,
not comprehensive DLP. Artifacts store only normalized text in a private attempt
directory; handles are scoped to the session and never public filesystem paths.

## Paired evaluation

`public-tasks.json` contains 20 public greenfield development tasks; `frozen-suite.json`
locks their exact specs and ordering. The generator may see these public specs.
Independent evaluators own acceptance tests and outcomes; protected holdouts never
enter candidate diagnostic traces. Freeze or replace the suite only before a run.

```sh
python3 crates/execution/harness/harness_evaluation.py gate \
  crates/execution/harness/frozen-suite.json /private/independent-receipts.json
```

Input is a JSON list of 120 trusted run receipts: one `baseline` and one `candidate`
for each `task_id`, each `repeat` 0–2. Required fields are `suite_sha256`, `goose_build`,
`profile`, `model`, `route` (reviewed route-snapshot identity), `budget` (integer
microusd), `accepted`, `independent`, `safety_passed`, `billed_microusd`, `elapsed_ms`.
The gate validates pairs, completeness and measurements; it does not authenticate
self-asserted receipt flags. The trusted evaluator/collector must supply these
receipts from independent evidence, not from generator output.

Per-task cost/time is total across its three repetitions divided by accepted
repetitions; failed runs therefore count toward cost. Compare medians across the
20 tasks. Every task must have an accepted run, total accepted runs cannot decline,
cost must improve at least 10%, and time may grow at most 10%. Unknown data,
unsafe runs, unpaired routing/budgets or incomplete evidence fail closed. Even a
passing report always emits `candidate_enabled:false`: it never grants admission.
No live benchmark or claimed savings is included in this repository milestone.

## Remaining admission work

The general script capability needs a reviewed protected relay/launcher contract,
actual pinned-Goose MCP integration proof, bounded production broker transport
proof, independent safety evidence, and the 120-run model comparison after the
existing correctness/runtime gaps close. That boundary is intentionally not
widened by importing this module. Phase 11A and Phase 12 remain incomplete.
