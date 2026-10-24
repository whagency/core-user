CREATE TABLE IF NOT EXISTS two_factor_settings (
    user_id BIGINT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE ON UPDATE CASCADE,
    contact_id BIGINT REFERENCES contacts(id) ON DELETE SET NULL ON UPDATE CASCADE,
    method SMALLINT NOT NULL,
    secret VARCHAR(255),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_two_factor_settings_user_id ON two_factor_settings(user_id);
CREATE INDEX IF NOT EXISTS idx_two_factor_settings_contact_id ON two_factor_settings(contact_id);