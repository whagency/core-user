CREATE EXTENSION IF NOT EXISTS pg_stat_statements;

CREATE SEQUENCE IF NOT EXISTS users_user_number_seq
    START 124912072
    INCREMENT BY 1
    MINVALUE 124912072;

CREATE TABLE IF NOT EXISTS users (
    id BIGSERIAL PRIMARY KEY,
    user_number INTEGER NOT NULL UNIQUE DEFAULT nextval('users_user_number_seq'),
    primary_contact_id BIGINT NULL,
    status SMALLINT NOT NULL,
    verification_level SMALLINT NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NULL,
    deleted_at TIMESTAMPTZ NULL
);

CREATE INDEX IF NOT EXISTS idx_users_status ON users(status);
CREATE INDEX IF NOT EXISTS idx_users_primary_contact_id ON users(primary_contact_id);