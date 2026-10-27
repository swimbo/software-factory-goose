-- Retained event delivery and its read snapshot commit together. The Restate journal remains
-- authoritative; this table does not grant leases or authorize mutations.
CREATE TABLE claim_lease_projection (
    work_package_id TEXT PRIMARY KEY,
    version BIGINT NOT NULL CHECK (version > 0),
    snapshot JSONB NOT NULL
);
-- A task version cannot silently acquire a second event identity, including old versions.
CREATE UNIQUE INDEX outbox_claim_version ON outbox
    ((payload->>'work_package_id'), ((payload->>'version')::bigint))
    WHERE step_kind = 'claim_transition_v1';
