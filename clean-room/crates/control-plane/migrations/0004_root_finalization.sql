-- Derived view only. The immutable claim-object envelope remains authoritative.
CREATE TABLE root_finalization_projection (
    task_id TEXT PRIMARY KEY,
    generation TEXT NOT NULL UNIQUE,
    event_version BIGINT NOT NULL CHECK (event_version = 1),
    payload_sha256 TEXT NOT NULL CHECK (payload_sha256 ~ '^[0-9a-f]{64}$'),
    payload JSONB NOT NULL
);
