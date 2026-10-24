CREATE TABLE IF NOT EXISTS verifications (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE ON UPDATE CASCADE,
    verification_level SMALLINT NOT NULL DEFAULT 1,
    provider SMALLINT NOT NULL,
    status SMALLINT NOT NULL,
    external_id VARCHAR(128),
    provider_data JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NULL
);

CREATE INDEX IF NOT EXISTS idx_verifications_provider_external_id ON verifications(provider, external_id);
CREATE INDEX IF NOT EXISTS idx_verifications_user_provider ON verifications(user_id, provider);