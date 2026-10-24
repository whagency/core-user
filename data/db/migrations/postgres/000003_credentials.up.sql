CREATE TABLE IF NOT EXISTS credentials (
    user_id BIGINT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE ON UPDATE CASCADE,
    password_hash TEXT NOT NULL,
    algorithm VARCHAR(32) NOT NULL,
    password_updated_at TIMESTAMPTZ NULL,
    must_rotate BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE INDEX IF NOT EXISTS idx_credentials_user_id ON credentials(user_id);