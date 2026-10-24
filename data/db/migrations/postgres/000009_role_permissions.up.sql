CREATE TABLE IF NOT EXISTS role_permissions (
    name VARCHAR(20) REFERENCES roles(name) ON DELETE CASCADE ON UPDATE CASCADE,
    permission VARCHAR(50) REFERENCES permissions(permission) ON DELETE CASCADE ON UPDATE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (name, permission)
);

CREATE INDEX IF NOT EXISTS idx_role_permissions_name ON role_permissions(name);
CREATE INDEX IF NOT EXISTS idx_role_permissions_permission ON role_permissions(permission);