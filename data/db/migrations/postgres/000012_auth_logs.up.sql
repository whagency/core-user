CREATE TABLE IF NOT EXISTS auth_logs (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT REFERENCES users(id) ON DELETE SET NULL ON UPDATE CASCADE,
    ip VARCHAR(100) NOT NULL,
    agent VARCHAR(255),
    browser VARCHAR(255),
    device VARCHAR(255),
    city VARCHAR(255),
    region VARCHAR(255),
    anonymous_data JSONB,
    status SMALLINT NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_auth_logs_user_id ON auth_logs(user_id);
