-- Control-plane queryable records (consensus R3): Postgres is a *read projection* fed by an
-- idempotent outbox from the Restate journal. It is NOT a second source of truth.

-- Outbox: journaled events, consumed by a relay that upserts the projection.
CREATE TABLE IF NOT EXISTS outbox (
    invocation_id  TEXT NOT NULL,
    step_seq       BIGINT NOT NULL,
    step_kind      TEXT NOT NULL,
    payload        JSONB NOT NULL,
    PRIMARY KEY (invocation_id, step_seq)
);

-- Qualifier decisions (queryable by `sfctl inspect`).
CREATE TABLE IF NOT EXISTS qualifier_decisions (
    intent_id   TEXT PRIMARY KEY,
    score       DOUBLE PRECISION NOT NULL,
    lane        TEXT NOT NULL,
    reason      TEXT NOT NULL,
    fatal       BOOLEAN NOT NULL
);

-- Work packages (projected lifecycle; authoritative state is the Restate journal).
CREATE TABLE IF NOT EXISTS work_packages (
    id            TEXT PRIMARY KEY,
    intent_id     TEXT NOT NULL,
    stage         TEXT NOT NULL,
    attempts      INTEGER NOT NULL DEFAULT 0,
    unit_spent_usd DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    git_revision  TEXT
);

-- Receipts bound to an exact git revision (R6).
CREATE TABLE IF NOT EXISTS receipts (
    id            TEXT PRIMARY KEY,
    work_package_id TEXT NOT NULL,
    status        TEXT NOT NULL,
    git_revision  TEXT,
    wall_time_ms  BIGINT,
    turn_count    INTEGER,
    exit_code     INTEGER,
    diff          TEXT
);

-- Append-only audit log ("lights off, nothing unseen").
CREATE TABLE IF NOT EXISTS audit_events (
    id          TEXT PRIMARY KEY,
    timestamp   TIMESTAMPTZ NOT NULL DEFAULT now(),
    actor       TEXT NOT NULL,
    action      TEXT NOT NULL,
    entity_id   TEXT NOT NULL,
    entity_type TEXT NOT NULL,
    metadata    JSONB
);

CREATE INDEX IF NOT EXISTS idx_audit_entity ON audit_events (entity_id);
CREATE INDEX IF NOT EXISTS idx_wp_stage ON work_packages (stage);
