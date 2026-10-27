# Diagnostic qualifier projection boundary

The diagnostic `POST /v1/intents` uses provisional, partly hard-coded features. Its response
is labelled `diagnostic_only`; it is not a durable qualification or scheduling authority.
Previously the handler also wrote that decision to `qualifier_decisions`, which has no field
for that label. The handler no longer writes to that table. It still returns the diagnostic
response and retains its in-memory demonstration pipeline.

The disposable PostgreSQL fixture `clean-room/tests/fixtures/diagnostic_projection.py`
started a fresh, isolated PostgreSQL 17 cluster and ran the explicitly ignored database test.
Before the fix, the test failed because submitting the diagnostic request inserted one row.
After the fix, the same request left the table empty. A separate direct projection call
inserted a row, confirming the existing projection function remains usable; that control is
not proof of a journal-backed qualifier. The fixture owns and stops only its own process and
temporary data. No standing database or production service was touched.

Previously written diagnostic rows are not identified or removed by this change. Trusted
repository resolution, grounded features, qualification authority, journal-derived projection,
intake-to-task binding, and any migration of existing ambiguous rows remain open.
