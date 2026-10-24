CREATE TABLE IF NOT EXISTS revoked_sessions (
    uuid UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE ON UPDATE CASCADE,
    reason SMALLINT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expire_at TIMESTAMPTZ NULL
);

CREATE INDEX IF NOT EXISTS idx_revoked_sessions_user_id ON revoked_sessions(user_id);
