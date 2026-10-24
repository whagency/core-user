CREATE TABLE IF NOT EXISTS two_factor_tokens (
    uuid UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE ON UPDATE CASCADE,
    contact_id BIGINT REFERENCES contacts(id) ON DELETE CASCADE ON UPDATE CASCADE,
    type SMALLINT NOT NULL,
    method SMALLINT NOT NULL,
    secret VARCHAR(255),
    code_hash VARCHAR(255),
    code_salt VARCHAR(255),
    attempts SMALLINT NOT NULL DEFAULT 0,
    status SMALLINT NOT NULL DEFAULT 1,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    dispatched_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_two_factor_tokens_user_type ON two_factor_tokens(user_id, type);
CREATE INDEX IF NOT EXISTS idx_two_factor_tokens_contact_type ON two_factor_tokens(contact_id, type);