-- +goose Up
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    google_id TEXT NOT NULL UNIQUE,
    email TEXT NOT NULL,
    name TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL
);

CREATE TABLE IF NOT EXISTS api_keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id),
    key_hash TEXT NOT NULL UNIQUE,
    key_prefix TEXT NOT NULL,
    label TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_api_keys_user_id ON api_keys(user_id);
CREATE INDEX IF NOT EXISTS idx_api_keys_key_hash ON api_keys(key_hash);

-- paused_at is set while the channel refuses new hooks.
CREATE TABLE IF NOT EXISTS channels (
    name TEXT PRIMARY KEY,
    paused_at TIMESTAMP
);

-- A guard is a configured check hooks must pass (see internal/guard). secret
-- is the name of the secret it checks with, a CATCHY_SECRET_ environment
-- variable. options is a JSON object of
-- scheme settings, e.g. the signature header.
CREATE TABLE IF NOT EXISTS guards (
    name TEXT PRIMARY KEY,
    type TEXT NOT NULL,
    scheme TEXT NOT NULL DEFAULT '',
    options TEXT NOT NULL DEFAULT '{}',
    secret TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS channels_guards (
    channel TEXT NOT NULL REFERENCES channels(name) ON DELETE CASCADE,
    guard TEXT NOT NULL REFERENCES guards(name),
    PRIMARY KEY (channel, guard)
);

CREATE INDEX IF NOT EXISTS idx_channels_guards_guard ON channels_guards(guard);

-- Every instance starts with a ready-made honeypot guard to attach to form
-- channels.
INSERT INTO guards (name, type, options) VALUES ('honeypot', 'honeypot', '{"field":"_gotcha"}');

-- id is a lowercase ULID, so ordering by id is ordering by time caught.
-- body is the only copy of what was sent; the payload is decoded from it on read.
CREATE TABLE IF NOT EXISTS hooks (
    id TEXT PRIMARY KEY,
    channel TEXT NOT NULL REFERENCES channels(name) ON DELETE CASCADE,
    status TEXT NOT NULL DEFAULT 'pending',
    method TEXT NOT NULL,
    query TEXT NOT NULL DEFAULT '',
    headers TEXT NOT NULL DEFAULT '{}',
    content_type TEXT NOT NULL DEFAULT '',
    body BLOB NOT NULL,
    ip TEXT NOT NULL DEFAULT '',
    failures TEXT NOT NULL DEFAULT '[]',
    created_at TIMESTAMP NOT NULL,
    finalized_at TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_hooks_channel_id ON hooks(channel, id);
CREATE INDEX IF NOT EXISTS idx_hooks_status_id ON hooks(status, id);

-- A destination is where hooks are delivered, over a protocol (http).
-- options is a JSON object of its settings: URL, headers, and body are
-- templates, which use secrets by name, like {{.Secrets.NAME}}.
CREATE TABLE IF NOT EXISTS destinations (
    name TEXT PRIMARY KEY,
    protocol TEXT NOT NULL,
    options TEXT NOT NULL DEFAULT '{}',
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS channels_destinations (
    channel TEXT NOT NULL REFERENCES channels(name) ON DELETE CASCADE,
    destination TEXT NOT NULL REFERENCES destinations(name),
    PRIMARY KEY (channel, destination)
);

CREATE INDEX IF NOT EXISTS idx_channels_destinations_destination ON channels_destinations(destination);

-- A delivery is one try at sending a hook to a destination; a
-- destination's state for a hook is its latest try. Pending tries are sent
-- when due_at comes. A failed try schedules the next as a new row, with
-- attempt counting up, until retries run out.
CREATE TABLE IF NOT EXISTS deliveries (
    id TEXT PRIMARY KEY,
    hook_id TEXT NOT NULL REFERENCES hooks(id) ON DELETE CASCADE,
    destination TEXT NOT NULL,
    attempt INTEGER NOT NULL DEFAULT 1,
    status TEXT NOT NULL DEFAULT 'pending',
    due_at TIMESTAMP NOT NULL,
    http_status INTEGER NOT NULL DEFAULT 0,
    error TEXT NOT NULL DEFAULT '',
    ms INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMP NOT NULL,
    finished_at TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_deliveries_due ON deliveries(status, due_at);
CREATE INDEX IF NOT EXISTS idx_deliveries_hook ON deliveries(hook_id, destination, id);

-- +goose Down
DROP TABLE IF EXISTS deliveries;
DROP TABLE IF EXISTS channels_destinations;
DROP TABLE IF EXISTS destinations;
DROP TABLE IF EXISTS hooks;
DROP TABLE IF EXISTS channels_guards;
DROP TABLE IF EXISTS guards;
DROP TABLE IF EXISTS channels;
DROP TABLE IF EXISTS api_keys;
DROP TABLE IF EXISTS users;
