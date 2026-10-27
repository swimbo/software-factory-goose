# Disposable claim-key discovery experiment

**Result: PASS for the fixture only.** This does not close G-01 or establish an authoritative recovery inventory.

Command from the repository root:

```sh
python3 clean-room/tests/fixtures/claim_projection_recovery.py
```

The test used the existing built `claim_recovery_fixture` executable (SHA-256 `252e33e2fe21033e4ceac3e8c152c65213a432aec7e25899bf017f92face789d`) with an isolated local Restate 1.8.0 process and a newly created PostgreSQL 17 fixture cluster (pgvector 0.8.2). The fixture script SHA-256 was `aa145fc6fb80e90c1ca7b5cff23076a6396ecf8f0ec22f1c7a56c1b9c4f5625a`. Only the fixture-owned `sfactory_verification` database was dropped and recreated; the test cleaned up its processes and temporary files.

The fixture used the Restate admin SQL endpoint to select `service_key` only from the `state` table for `service_name = 'ClaimLeaseJournal'` and state key `claim`. It initialized two synthetic claim objects, verified discovery of exactly those two keys (a status call on an uninitialized key did not create a third), dropped and recreated the fixture SQL database, killed and restarted the fixture Restate process, and rediscovered the same keys. Fresh re-export calls for both discovered keys restored their original per-object event records, including IDs. Existing conflict rollback, permanent quarantine, and 128-event retention-cap assertions also passed. The command returned `result: PASS` and `admin_discovery_fixture_keys: 2`.

**Limits:** This is a read-only introspection experiment, not a production inventory or a recovery API. It does not establish that queries return a consistent or complete set under concurrent initialization, in-flight crashes, other Restate versions, distributed partitions, retention, deleted or corrupt state, or total journal loss. It does not enumerate other object types or verify filtering against another registered service. Access to admin SQL is privileged and its production authentication and network isolation were not tested. It neither clears quarantine nor authorizes resumed work. Every recovery still requires fresh invocation semantics and an independently reviewed completeness, access-control, and reconciliation protocol. No production deployment, real credential, standing service, or worker was touched.
