# Unscoped memory route

The diagnostic `/v1/memory/dependents/{symbol}` route previously queried a global AST table without caller identity, repository or revision scope and returned database errors directly. It now returns a static unavailable response until those boundaries exist. The graph query helper remains available to trusted code; this change does not implement scoped indexing or semantic recall.

The local route test first observed HTTP 200 instead of unavailable and passed after the change. A separate fresh PostgreSQL fixture inserted a synthetic edge, confirmed that a trusted direct query could retrieve its caller, and verified that the public diagnostic route returned 503 without disclosing it. No production data was read or modified. Logs: `2026-10-27-memory-unscoped-red.log`, `2026-10-27-memory-unscoped-green.log`, and `2026-10-27-memory-private-db.log`.
