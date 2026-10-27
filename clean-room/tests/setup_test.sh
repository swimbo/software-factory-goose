#!/usr/bin/env bash
# Isolated command fixtures only: never calls Docker daemon or network.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
fixture=$(mktemp -d)
trap 'rm -rf "$fixture"' EXIT
mkdir "$fixture/bin"
cat > "$fixture/bin/docker" <<'MOCK'
#!/bin/bash
printf '%s\n' "$*" >> "$FIXTURE_LOG"
case "$*" in
  *' up '*) exit "${FIXTURE_UP_STATUS:-0}" ;;
  *'psql'*) printf '%s\n' "${FIXTURE_VECTOR_AVAILABLE:-1}"; exit 0 ;;
  *'pg_isready'*) exit "${FIXTURE_PG_STATUS:-0}" ;;
esac
exit 0
MOCK
cat > "$fixture/bin/curl" <<'MOCK'
#!/bin/bash
printf 'curl %s\n' "$*" >> "$FIXTURE_LOG"
if [[ "$*" == *'/health'* ]]; then exit "${FIXTURE_HEALTH_STATUS:-0}"; fi
if [[ "${FIXTURE_REGISTER_STATUS:-0}" != 0 ]]; then exit "$FIXTURE_REGISTER_STATUS"; fi
printf '%s\n' "${FIXTURE_RESPONSE:-null}"
MOCK
cat > "$fixture/bin/sleep" <<'MOCK'
#!/bin/bash
exit 0
MOCK
chmod +x "$fixture/bin/"*
export PATH="$fixture/bin:$PATH" FIXTURE_LOG="$fixture/calls" RESTATE_IMAGE='docker.restate.dev/restatedev/restate:1.6.0' POSTGRES_PASSWORD='fixture-only-password'
: > "$FIXTURE_LOG"

if "$root/setup.sh" check >"$fixture/out" 2>&1; then :; else cat "$fixture/out"; exit 1; fi
if grep -q ' up ' "$FIXTURE_LOG"; then echo 'check must never start services'; exit 1; fi

export FIXTURE_HEALTH_STATUS=22
if "$root/setup.sh" up >"$fixture/out" 2>&1; then echo 'unhealthy admin must fail'; exit 1; fi
if grep -q 'Infrastructure ready' "$fixture/out"; then echo 'false readiness'; exit 1; fi
unset FIXTURE_HEALTH_STATUS

export FIXTURE_UP_STATUS=1
if "$root/setup.sh" up >"$fixture/out" 2>&1; then echo 'compose failure must propagate'; exit 1; fi
unset FIXTURE_UP_STATUS

export FIXTURE_PG_STATUS=1
if "$root/setup.sh" up >"$fixture/out" 2>&1; then echo 'unready database must fail'; exit 1; fi
unset FIXTURE_PG_STATUS
export FIXTURE_VECTOR_AVAILABLE=0
if "$root/setup.sh" up >"$fixture/out" 2>&1; then echo 'missing vector extension must fail'; exit 1; fi
unset FIXTURE_VECTOR_AVAILABLE

unset SFACTORY_SDK_URI || true
if "$root/setup.sh" register >"$fixture/out" 2>&1; then echo 'missing SDK URI must fail'; exit 1; fi
export SFACTORY_SDK_URI='http://private-fixture:9080' FIXTURE_REGISTER_STATUS=22
if "$root/setup.sh" register >"$fixture/out" 2>&1; then echo 'registration HTTP failure must fail'; exit 1; fi
unset FIXTURE_REGISTER_STATUS
export FIXTURE_RESPONSE='{}'
if "$root/setup.sh" register >"$fixture/out" 2>&1; then echo 'missing discovered services must fail'; exit 1; fi
export FIXTURE_RESPONSE='{"id":"dp-fixture","services":[{"name":"WorkPackageWorkflow"},{"name":"BudgetCounter"}]}'
"$root/setup.sh" register >"$fixture/out" 2>&1
if grep -q 'fixture-only-password' "$fixture/out"; then echo 'secret printed'; exit 1; fi
: > "$FIXTURE_LOG"
"$root/setup.sh" up >"$fixture/out" 2>&1
if grep -q '/deployments' "$FIXTURE_LOG"; then echo 'up must not auto-register'; exit 1; fi
printf 'setup fixtures passed\n'
