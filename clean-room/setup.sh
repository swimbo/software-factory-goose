#!/usr/bin/env bash
set -euo pipefail

# Explicit stages prevent registration before the SDK/private ingress is running.
# Bifrost is external; this script neither starts nor configures it.
cd "$(dirname "$0")"
mode=${1:-check}
fail() { echo "setup: $*" >&2; exit 1; }
case "$mode" in check|up|register) ;; *) fail 'usage: ./setup.sh [check|up|register]' ;; esac

command -v docker >/dev/null || fail 'Docker Compose is required'
[[ -n "${RESTATE_IMAGE:-}" ]] || fail 'set RESTATE_IMAGE to a reviewed server version or immutable digest; SDK version is not server version'
[[ "$RESTATE_IMAGE" != *:latest && "$RESTATE_IMAGE" != *:main ]] || fail 'floating Restate latest/main images are not accepted'
[[ "$RESTATE_IMAGE" == *@sha256:* || "$RESTATE_IMAGE" =~ :[0-9]+\.[0-9]+\.[0-9]+$ ]] || fail 'RESTATE_IMAGE must have an explicit release version or sha256 digest'
[[ -n "${POSTGRES_PASSWORD:-}" ]] || fail 'set POSTGRES_PASSWORD locally; no default password is provided'
docker compose -f compose.yaml config --quiet
if [[ "$mode" == check ]]; then
  echo 'Configuration validated only; no services started and no runtime readiness claimed.'
  exit 0
fi
command -v curl >/dev/null || fail 'curl is required'
admin_url=http://127.0.0.1:9070

wait_admin() {
  for ((attempt=0; attempt<30; attempt++)); do
    if curl --fail --silent --connect-timeout 1 --max-time 2 "$admin_url/health" >/dev/null 2>&1; then return 0; fi
    sleep 1
  done
  fail 'Restate admin health timed out; infrastructure may be running, but setup is incomplete'
}

if [[ "$mode" == up ]]; then
  docker compose -f compose.yaml up -d --no-recreate postgres restate
  wait_admin
  database_ready=false
  for ((attempt=0; attempt<30; attempt++)); do
    if docker compose -f compose.yaml exec -T postgres pg_isready -U sfactory -d sfactory >/dev/null 2>&1; then database_ready=true; break; fi
    sleep 1
  done
  [[ "$database_ready" == true ]] || fail 'Postgres readiness timed out; setup is incomplete'
  vector_available=$(docker compose -f compose.yaml exec -T postgres psql -U sfactory -d sfactory -tAc "SELECT count(*) FROM pg_available_extensions WHERE name = 'vector'")
  [[ "$vector_available" == 1 ]] || fail 'Postgres vector extension is unavailable; migration 0002 cannot run'
  echo 'Infrastructure ready for further verification: Restate ingress 127.0.0.1:8090, admin 127.0.0.1:9070, Postgres 127.0.0.1:5432.'
  echo 'Next: start the host control plane and verify its private SDK ingress; registration is a separate explicit step. See SETUP.md.'
  echo 'Migrations, durable replay, worker isolation, approval authority, and Bifrost readiness are not established by this check.'
  exit 0
fi

# Register only after the operator has configured a reachable private SDK ingress. The host
# binary's loopback-only :9080 is not assumed reachable from the Docker container.
command -v python3 >/dev/null || fail 'python3 is required to validate the registration payload/response'
[[ -n "${SFACTORY_SDK_URI:-}" ]] || fail 'set SFACTORY_SDK_URI to the reviewed private SDK ingress; host loopback is not Docker reachability proof'
workdir=$(mktemp -d)
trap 'rm -rf "$workdir"' EXIT
python3 - "$workdir/request.json" <<'PY'
import json, os, sys
from urllib.parse import urlsplit
uri = os.environ['SFACTORY_SDK_URI']
u = urlsplit(uri)
if u.scheme not in ('http', 'https') or not u.hostname or u.username or u.password or u.query or u.fragment or any(c.isspace() for c in uri):
    raise SystemExit('setup: SDK URI must be HTTP(S), without credentials, query, fragment, or whitespace')
if u.hostname in ('localhost', '127.0.0.1', '::1'):
    raise SystemExit('setup: Docker Restate cannot use its own loopback to reach the host SDK')
with open(sys.argv[1], 'w') as f:
    json.dump({'uri': uri}, f)
PY
wait_admin
# Non-2xx, timeout, malformed JSON, or missing service discovery is a hard failure.
# Never echo server responses or interpolate credentials into command lines.
curl --fail --silent --show-error --connect-timeout 2 --max-time 20 \
  -X POST "$admin_url/deployments" -H 'content-type: application/json' \
  --data-binary "@$workdir/request.json" > "$workdir/response.json"
python3 - "$workdir/response.json" <<'PY'
import json, sys
try:
    with open(sys.argv[1]) as f:
        response = json.load(f)
    names = {s['name'] for s in response['services']}
    if not isinstance(response.get('id'), str) or not response['id'] or not {'WorkPackageWorkflow', 'BudgetCounter'} <= names:
        raise ValueError('incomplete discovery')
except (ValueError, KeyError, TypeError):
    raise SystemExit('setup: registration did not return the expected workflow and budget services')
print('Diagnostic workflow and budget service registration confirmed; privileged approval journal and live workers remain unavailable.')
PY
