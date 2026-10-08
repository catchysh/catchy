-- +goose Up
CREATE TABLE IF NOT EXISTS users (
    id BIGSERIAL PRIMARY KEY,
    google_id TEXT NOT NULL UNIQUE,
    email TEXT NOT NULL,
    name TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS api_keys (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL REFERENCES users(id),
    key_hash TEXT NOT NULL UNIQUE,
    key_prefix TEXT NOT NULL,
    label TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_api_keys_user_id ON api_keys(user_id);
CREATE INDEX IF NOT EXISTS idx_api_keys_key_hash ON api_keys(key_hash);

-- paused_at is set while the channel refuses new hooks.
CREATE TABLE IF NOT EXISTS channels (
    name TEXT PRIMARY KEY,
    paused_at TIMESTAMPTZ
);

-- A guard is a configured check hooks must pass (see internal/guard). secret
-- is sealed with ENCRYPTION_KEY; secret_hint is a short masked form to show.
-- options is a JSON object of scheme settings, e.g. the signature header.
CREATE TABLE IF NOT EXISTS guards (
    name TEXT PRIMARY KEY,
    type TEXT NOT NULL,
    scheme TEXT NOT NULL DEFAULT '',
    options TEXT NOT NULL DEFAULT '{}',
    secret TEXT NOT NULL DEFAULT '',
    secret_hint TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
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
    body BYTEA NOT NULL,
    ip TEXT NOT NULL DEFAULT '',
    failures TEXT NOT NULL DEFAULT '[]',
    created_at TIMESTAMPTZ NOT NULL,
    finalized_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_hooks_channel_id ON hooks(channel, id);
CREATE INDEX IF NOT EXISTS idx_hooks_status_id ON hooks(status, id);

-- +goose Down
DROP TABLE IF EXISTS hooks;
DROP TABLE IF EXISTS channels_guards;
DROP TABLE IF EXISTS guards;
DROP TABLE IF EXISTS channels;
DROP TABLE IF EXISTS api_keys;
DROP TABLE IF EXISTS users;
