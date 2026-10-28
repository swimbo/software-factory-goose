# Proposed factory key expiry and budget update — review only

Read-only on `hermes-control`: the file `/home/bo/.hermes/bifrost/factory-secrets/software-factory-goose/credential` was loaded only into a trusted host process and compared in memory, using `hmac.compare_digest`, to the value for the unique named SQLite row. The boolean result was **true**; neither credential nor hash was returned, logged, or written. The exact key ID is `7a7668ab-825d-437a-8afa-36cdf8b7a906`. A separate metadata query showed it active, with no expiry, no key-level or linked provider budget, and no team/customer budget association. The three auto-route rules remain scoped to that key and have no fallbacks.

## Prepared request, not executed

Current upstream [virtual-key documentation](https://github.com/maximhq/bifrost/blob/dev/docs/features/governance/virtual-keys.mdx) describes the following update shape for expiry plus a new key budget. This is a **candidate for the deployed-version schema**, not an authorized or verified update; the running container image is pinned only by digest and its unauthenticated OpenAPI/version endpoints did not yield a schema.

```http
PUT /api/governance/virtual-keys/7a7668ab-825d-437a-8afa-36cdf8b7a906
Content-Type: application/json
Authorization: <privileged operator authentication supplied through a protected channel>

{
  "expires_at": "<RFC3339 time no later than min(now + 15 minutes, task lease expiry)>",
  "budgets": [{"max_limit": 0.75, "reset_duration": "1d"}]
}
```

This contains no secret and is not an executable command. `expires_at` cannot be finalized until the actual task lease and execution window are known. The one-day reset is only a gateway defense in depth: the factory's integer reservation ledger must enforce the cumulative non-resetting `750000` microUSD cap across concurrency, retries, key expiration and renewal. A gateway budget does not prove a worst-case reservation or provider charging bound.

**Before any write:** identify a separately authenticated management credential with authority to update this exact key, without using the existing desktop virtual key. The current compose file exposes no documented management-auth variable name, and no admin credential or authenticated API access was established by this check. Determine the running image version and exact `PUT` schema, including whether adding a budget to an existing key is supported and whether omitted provider/key associations remain unchanged; upstream versions differ, so do not assume this current documentation applies. Verify no request or response body containing a key is printed or persisted.

Capture only non-secret structured metadata for this key and the desktop rules before the candidate update. Update only the identified factory key through the supported admin API, then read back expiry, budget, provider/model restrictions and routing rules without exposing credentials. Verify no desktop or unrelated policy changes. Independently test expiry/revocation, $0.75 accounting under concurrency and route/fallback cost limits using a controlled fixture before spending. Missing pricing, token ceilings, tool payload accounting, private ingress, routing/egress containment and production activation are still separate gates.

No update, provider inference, service restart, database mutation or key creation occurred during this check.
