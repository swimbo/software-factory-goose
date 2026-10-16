#!/usr/bin/env bash
set -euo pipefail

# Clean-room software factory — bring up the factory's infra + register the SDK service.
# The Bifrost model gateway runs externally (your network); point at it with BIFROST_URL.
# Usage:  ./setup.sh
cd "$(dirname "$0")"

echo "==> Starting factory infra (restate + postgres)"
docker compose up -d

echo "==> Waiting for restate admin API"
for _ in $(seq 1 30); do
  if curl -sf localhost:9071/health >/dev/null 2>&1; then break; fi
  sleep 1
done

echo "==> Registering the control-plane SDK service (workflow + budget object) with Restate"
curl -s -X POST localhost:9071/deployments \
  -H 'content-type: application/json' \
  -d '{"uri":"http://host.docker.internal:9080"}' \
  || echo "  (registration skipped — is the control-plane running on :9080?)"

echo
echo "==> Infra is up. Now start the planes:"
echo "  export BIFROST_URL=http://<your-bifrost-host>:8080   # your Bifrost gateway"
echo "  export BIFROST_VK=sk-bf-...        # virtual key (sent as x-bf-vk)"
echo "  export BIFROST_ADMIN_KEY=...      # management bearer (governance budget reads)"
echo "  export DATABASE_URL=postgres://sfactory:sfactory@localhost:5432/sfactory"
echo "  cargo run -p control-plane --features restate   # Axum :8081, Restate SDK :9080"
echo "  sfctl submit --title '...' --description '...' --acceptance 'has a passing test'"
