CREATE TABLE IF NOT EXISTS roles (
    name VARCHAR(20) PRIMARY KEY,
    description VARCHAR(100),
    created_at timestamptz NOT NULL DEFAULT NOW(),
    updated_at timestamptz NULL
);