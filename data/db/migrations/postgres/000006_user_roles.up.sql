CREATE TABLE IF NOT EXISTS user_roles (
    name VARCHAR(20) REFERENCES roles(name) ON DELETE CASCADE ON UPDATE CASCADE,
    user_id BIGINT REFERENCES users(id) ON DELETE CASCADE ON UPDATE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (name, user_id)
);

CREATE INDEX IF NOT EXISTS idx_user_roles_name ON user_roles(name);
CREATE INDEX IF NOT EXISTS idx_user_roles_user_id ON user_roles(user_id);