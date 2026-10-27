# Offline Goose project-hook spike

Date: 2026-10-27. **The no-profile-only exclusion hypothesis is falsified.** The exact audited v1.49.0 binary executed a harmless project `SessionStart` hook while running a fresh `--no-profile --no-session` invocation with no advertised tools. This does not rule out a separately protected launch arrangement or narrow patch. It does not pass T6 or enable factory workers.

## Reproducible artifacts

- [Script](goose_hook_spike.py), SHA-256 `b3fbe0c3bb169320a31a754c1b84ed921d228d25223be6e46fb63453c441d95c`.
- [Observed summary](2026-10-27-goose-hook-spike.json).
- [Binary provenance](2026-10-26-goose-protocol.md): official archive digest verified before its earlier extraction; this script independently rechecks executable SHA-256 `6bc711de29cd43bcf1e3ac7a3193b453dd0348068192947079c3cb871542319c` and version `1.49.0` before each experiment run.

Run on Darwin arm64 with the audited binary already available:

```sh
python3 docs/planning/clean-room/verification/goose_hook_spike.py \
  --goose /absolute/path/to/audited/goose \
  --summary /absolute/path/to/new-evidence.json
```

The optional summary destination must not already exist. The script refuses a different binary digest or platform. Exit zero means the specific bypass was reproduced with valid controls; it does **not** mean the security boundary passed. Exit two means inconclusive. Setup failures stop before a security conclusion.

## Fixture boundary

Each case used a new isolated home, Goose config/data/state root, temporary directory, and work directory. Environment variables were constructed from an allowlist, including `GOOSE_PATH_ROOT`, local `OPENAI_HOST`, an explicitly synthetic API-key placeholder, disabled session naming, and disabled telemetry. No real credentials, user Goose configuration, external model, Bifrost instance, factory runtime, account provisioning, or standing service was used.

An ephemeral Python HTTP server bound `127.0.0.1` on an allocated port and returned deterministic OpenAI-format responses. Its text was `OFFLINE_STUB_OK`; usage values were synthetic fixture values, not measured spend. Authorization headers were not recorded. The server was shut down and closed in `finally`.

A narrowly scoped `sandbox-exec` profile denied network operations except TCP to that loopback port, denied writes outside the fixture directory (except `/dev/null`), and denied reads beneath the actual user home. Before Goose execution, a connection attempt to a TEST-NET address was required to return `EPERM`; it did. This is a test guard, **not validation of the factory's planned Seatbelt profile, separate-UID isolation, or full process-lifetime guarantees**. The profile initially rejected a numeric-host rule during construction; the final tested rule used Seatbelt's accepted `localhost` syntax. No Goose task ran under the rejected profile.

Every Goose case used:

```text
run --no-profile --no-session --max-turns 1 --output-format json
    --text "Offline fixture: reply with the provider's fixed text; call no tools."
```

The plugin was placed at `.agents/plugins/fixture-hook`, with a `SessionStart` command running a fixture script. That script drained stdin and wrote only `HOOK_EXECUTED` to its own `hook.marker`. The disabled control added the named plugin to project `disabledPlugins`. The marker is an independently read filesystem effect; it was never requested by the stub model or inferred from Goose text.

## Results

| Fresh-session case | Exit / timeout | Local provider requests | Advertised tools | Stub response observed | Hook marker |
| --- | --- | --- | --- | --- | --- |
| No project plugin | 0 / no | 1 | none | yes | absent |
| Project hook, no-profile | 0 / no | 1 | none | yes | `HOOK_EXECUTED` |
| Project hook explicitly disabled | 0 / no | 1 | none | yes | absent |

All requests went to `/v1/chat/completions`. All stderr captures were empty. The positive provider controls show each invocation reached the intended fixture. The enabled/disabled plugin pair attributes the side effect to project-hook discovery rather than a stale marker or a tool call. Every case used a different fresh directory.

The observed target result confirms the [pinned independent hook-loading path](https://github.com/aaif-goose/goose/blob/71fc4be1ed729e26b1dc0a4466abdd03be548a53/crates/goose/src/agents/agent.rs#L465-L472) and [default-enabled plugin discovery](https://github.com/aaif-goose/goose/blob/71fc4be1ed729e26b1dc0a4466abdd03be548a53/crates/goose/src/plugins/discovery.rs#L154-L183). Disabling one known fixture plugin is a control, not a general defense against newly named project plugins.

Additional protocol observation: with these exact flags, stdout begins with the Goose startup banner before the JSON body. Parsing the entire stdout as JSON fails. `--quiet` was not exercised; this report makes no claim about its behavior. The bypass finding does not depend on parsing JSON or trusting `metadata.status`.

## Limits and next decision

This is the first discovery canary only. It does not test factory MCP tool mediation, actual tool execution, secret masking, resource/media/notification variants, forged calls, subagents, resume, supervisor death, cancellation, budget reconciliation, or candidate-SHA verification. It cannot establish universal process cleanup or network isolation beyond the configured fixture guard and observed probe.

Raw stdout, stderr, request JSON, generated plugin/config files, and the sandbox profile remain in `/private/var/folders/3b/9571c77j0078bs3mpjrqcxj80000gn/T/sfactory-hook-spike-6dv34727`; these temporary files may expire. The durable script regenerates the fixture, and the summary preserves observed results. Nothing was copied into global Goose configuration or installed globally.

Stop the unqualified no-profile-only candidate. The next bounded decision is whether a protected working-directory arrangement can exclude workspace-origin executable discovery while retaining the required task semantics, or whether a narrow pinned change must disable that discovery. Either needs its own negative and positive canaries. Live execution remains blocked.
