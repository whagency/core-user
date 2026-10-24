CREATE TABLE IF NOT EXISTS password_change_logs (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE ON UPDATE CASCADE,
    ip VARCHAR(100) NOT NULL,
    user_agent VARCHAR(512),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_password_change_logs_user_id_created_at ON password_change_logs(user_id, created_at DESC);
