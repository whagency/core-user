CREATE TABLE IF NOT EXISTS sessions (
    uuid UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    expire INT NOT NULL DEFAULT 0,
    user_id BIGINT REFERENCES users(id) ON DELETE CASCADE ON UPDATE CASCADE,
    refresh_token VARCHAR(64) NOT NULL UNIQUE,
    ip VARCHAR(100) NOT NULL,
    agent VARCHAR(255),
    browser VARCHAR(255),
    device VARCHAR(255),
    city VARCHAR(255),
    region VARCHAR(255),
    anonymous_data JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_activity_at TIMESTAMPTZ NULL,
    refresh_expire INT NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
