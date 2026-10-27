# Local setup and readiness

`setup.sh` now defaults to configuration checking. It never starts services unless invoked
with `up`, and never registers an SDK service unless invoked separately with `register`.
Bifrost remains external and is not contacted, started, reconfigured, or credentialed here.

## Versions and configuration

Planning selects Rust 1.90, Restate **Rust SDK 0.12.1**, Postgres **16**, and
`pgvector/pgvector:pg16`. The SDK version does not identify the Restate server version.
Set `RESTATE_IMAGE` to a reviewed explicit server release (`major.minor.patch`) or immutable
digest. No server-version compatibility result is available from these fixture tests; do not
substitute SDK `0.12.1` as a server tag. `latest` is deliberately no longer a default.
`PGVECTOR_IMAGE` can override the planned pg16 image with a reviewed immutable pg16 digest.
The default pg16 tag floats; an immutable image selection remains needed for reproducible
runtime evidence. No image was pulled or service started during this repair.

Set `POSTGRES_PASSWORD` locally before invoking the script. There is no default password.
Do not put real credentials in commands copied into chat, logs, or tracked files. The script
expects exported variables, does not execute `.env` as shell code, and does not print resolved
Compose configuration or database URLs. Docker Compose may read `.env` for its own interpolation;
required script variables must still be present in the calling environment.

## Order of operations

1. Run `./setup.sh check`. This runs Compose configuration validation only and needs no daemon
   startup. Success means configuration syntax/interpolation passed, not that images exist or
   the infrastructure is usable.
2. When service startup is authorized, run `./setup.sh up`. It starts only Postgres and Restate,
   using `--no-recreate` to preserve existing containers, then checks the Restate admin health
   endpoint, database readiness, and availability of the
   vector extension required by migration `0002_memory.sql`. Timeouts or failures exit nonzero;
   partially started infrastructure is left intact for diagnosis. No deployment is registered.
3. Configure the host control plane's database connection locally and start it using
   `cargo run -p control-plane --features restate`. The control plane applies its SQL migrations.
   Verify those migrations separately; `up` does not claim to have applied them.
4. SDK registration remains conditional on a reviewed private ingress reachable **from the
   Restate container**. The current host SDK listener is `127.0.0.1:9080`; that alone does not
   prove Docker can reach it. Do not broaden the listener to all interfaces as a shortcut.
   No private ingress adapter or authentication is provisioned by this script.
5. Once that private ingress is actually established, set `SFACTORY_SDK_URI` to its HTTP(S)
   endpoint and run `./setup.sh register`. The script rejects host-loopback URI assumptions,
   HTTP errors, malformed response bodies, and missing discovery of `WorkPackageWorkflow` or
   `BudgetCounter`. The admin API performs service discovery during registration. No forced
   overwrite is requested. A successful response establishes diagnostic service registration
   only; it does not enable the unregistered approval journal or live workers.

## Ports and storage

| Surface | Host address | Container address |
|---|---|---|
| Restate ingress (`RESTATE_URL`) | `127.0.0.1:8090` | `8080` |
| Restate admin | `127.0.0.1:9070` | `9070` |
| Postgres | `127.0.0.1:5432` | `5432` |
| Host diagnostic HTTP API | `127.0.0.1:8081` | Not containerized |
| Host diagnostic SDK listener | `127.0.0.1:9080` | Not containerized |

The old script incorrectly treated 9071 as the admin port and 9070 as gRPC. No node-to-node
port is published for this single-node fixture. Local port binding is not a worker identity
boundary or authenticated private ingress.

For newly created containers, named volumes preserve Postgres data and Restate `/restate-data`; the Restate node name is
fixed so restarts address the same node directory. Volume configuration is not a tested
backup, restart-replay result, or crash-recovery proof. Do not delete existing volumes to
resolve a readiness error. Existing containers are not upgraded or recreated by `up`: an old
plain-Postgres container will fail the vector check. An old Restate container may still store
its journal only in its writable layer. Preserve/export that state and plan its migration
before explicitly recreating it; these new volume settings do not migrate existing data. Existing database credentials are not changed by setting a new
`POSTGRES_PASSWORD` for a previously initialized volume.

## Validation and remaining limits

`bash tests/setup_test.sh` replaces Docker, curl, and sleep with isolated local fixtures. It
checks read-only default checking, startup and health failure propagation, unavailable vector,
missing ingress URI, HTTP registration failure, incomplete discovery, successful discovery,
absence of automatic registration during `up`, and no password in final output. It neither
contacts Docker nor makes network requests. `bash -n` checks shell syntax. Real
`docker compose config --quiet` checks the configuration using placeholder environment values.

These checks do not prove image compatibility, image availability, SDK reachability, SQL
migration execution, durable replay, isolation, independent stop authority, or Bifrost budget
and credential enforcement. Those operating gates remain separate.

Sources checked 2026-10-26: [Restate Docker deployment](https://docs.restate.dev/server/deploy/docker)
for volume, fixed node name, and admin/ingress ports;
[deployment registration API](https://docs.restate.dev/admin-api/deployment/register-deployment)
for discovery and response contract; [pgvector](https://github.com/pgvector/pgvector)
for the extension-enabled Postgres image. Planning authority:
[tech guide](../docs/planning/clean-room/tech-guide.md).
