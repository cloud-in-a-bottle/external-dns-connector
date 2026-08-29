CREATE TABLE IF NOT EXISTS provider_accounts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    provider    TEXT NOT NULL,
    label       TEXT NOT NULL UNIQUE,
    -- JSON, unmarshalled directly into the libdns Provider struct for `provider`.
    credentials TEXT NOT NULL,
    created_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS zones (
    zone       TEXT PRIMARY KEY,
    account_id INTEGER NOT NULL REFERENCES provider_accounts(id) ON DELETE CASCADE,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS zones_account_id ON zones(account_id);

CREATE TABLE IF NOT EXISTS audit_log (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    ts           TEXT NOT NULL,
    actor        TEXT NOT NULL,
    actor_app_id TEXT NOT NULL DEFAULT '',
    op           TEXT NOT NULL,
    zone         TEXT NOT NULL DEFAULT '',
    detail       TEXT NOT NULL DEFAULT '',
    ok           INTEGER NOT NULL,
    error        TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS audit_log_ts ON audit_log(ts DESC);

-- Backing store for the built-in mock provider, so the whole record path is exercisable in tests
-- and in the UI without real registrar credentials.
CREATE TABLE IF NOT EXISTS mock_records (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    account_id INTEGER NOT NULL REFERENCES provider_accounts(id) ON DELETE CASCADE,
    zone       TEXT NOT NULL,
    name       TEXT NOT NULL,
    type       TEXT NOT NULL,
    ttl        INTEGER NOT NULL,
    data       TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS mock_records_zone ON mock_records(account_id, zone);
