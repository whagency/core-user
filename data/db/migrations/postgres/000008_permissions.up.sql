CREATE TABLE permissions (
    permission VARCHAR(50) PRIMARY KEY,
    description VARCHAR(150),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NULL
);